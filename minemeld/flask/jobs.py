#  Copyright 2017 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import uuid
import tempfile
import subprocess
import shutil
import json
import time
import signal
from collections import namedtuple, defaultdict

import redis
import psutil
import werkzeug.local
import gevent
from gevent.subprocess import Popen
from flask import g

from minemeld.utils import get_config_value
from . import config
from .logger import LOG


__all__ = ['init_app', 'JOBS_MANAGER']


REDIS_CP = redis.ConnectionPool.from_url(
    get_config_value(config, 'MGMTBUS.config.redis_url', 'unix:///var/run/redis/redis.sock'),
    max_connections=int(get_config_value(config, 'redis_max_connections', '5'))
)

REDIS_JOBS_GROUP_PREFIX = 'mm-jobs-{}'


_Job = namedtuple('_Job', field_names=['glet', 'timeout_glet'])


class JobsManager(object):
    def __init__(self, connection_pool):
        self.SR = redis.StrictRedis(connection_pool=connection_pool)
        self.running_jobs = defaultdict(dict)

    def _safe_rmtree(self, path):
        shutil.rmtree(path, ignore_errors=True)

    def _safe_remove(self, path):
        try:
            os.remove(path)
        except:
            pass

    def _get_job_status(self, jobpid, jobhash):
        try:
            jobprocess = psutil.Process(pid=jobpid)

        except psutil.NoSuchProcess:
            return {
                'status': 'DONE',
                'returncode': None
            }

        if hash(jobprocess) != jobhash:
            return {
                'status': 'DONE',
                'returncode': None
            }

        return {
            'status': 'RUNNING'
        }

    def _collect_job(self, jobdata):
        if 'collected' in jobdata:
            return

        tempdir = jobdata.get('cwd', None)
        if tempdir is not None:
            self._safe_rmtree(tempdir)

        jobdata['collected'] = True

    def _job_monitor_glet(self, job_group, jobid, description, args, data):
        jobname = (REDIS_JOBS_GROUP_PREFIX+'-{}').format(job_group, jobid)
        joblogfile = os.path.join(
            os.path.abspath(config.get('MINEMELD_LOG_DIRECTORY_PATH', '/tmp')),
            '{}.log'.format(jobname)
        )
        jobtempdir = tempfile.mkdtemp(prefix=jobname)

        LOG.info('Executing job {} - {} cwd: {} logfile: {}'.format(jobname, args, jobtempdir, joblogfile))

        try:
            with open(joblogfile, 'w+') as logfile:
                jobprocess = Popen(
                    args=args,
                    close_fds=True,
                    cwd=jobtempdir,
                    shell=False,
                    stdout=logfile,
                    stderr=subprocess.STDOUT
                )

        except OSError:
            self._safe_remove(joblogfile)
            self._safe_rmtree(jobtempdir)
            LOG.exception('Error starting job {}'.format(jobname))
            return

        jobpsproc = psutil.Process(pid=jobprocess.pid)

        jobdata = data
        if jobdata is None:
            jobdata = {}

        jobdata['create_time'] = int(time.time()*1000)
        jobdata['description'] = description
        jobdata['job_id'] = jobid
        jobdata['pid'] = jobpsproc.pid
        jobdata['hash'] = hash(jobpsproc)
        jobdata['logfile'] = joblogfile
        jobdata['cwd'] = jobtempdir
        jobdata['status'] = 'RUNNING'

        self.SR.hset(
            REDIS_JOBS_GROUP_PREFIX.format(job_group),
            jobid,
            json.dumps(jobdata)
        )

        jobprocess.wait()

        if jobprocess.returncode != 0:
            jobdata['status'] = 'ERROR'
        else:
            jobdata['status'] = 'DONE'
        jobdata['returncode'] = jobprocess.returncode
        jobdata['end_time'] = int(time.time()*1000)

        self._collect_job(jobdata)

        self.SR.hset(
            REDIS_JOBS_GROUP_PREFIX.format(job_group),
            jobid,
            json.dumps(jobdata)
        )

        job = self.running_jobs[job_group].pop(jobid, None)
        if job is not None and job.timeout_glet is not None:
            job.timeout_glet.kill()

        return jobprocess.returncode

    def _job_timeout_glet(self, job_group, jobid, timeout):
        gevent.sleep(timeout)

        prefix = REDIS_JOBS_GROUP_PREFIX.format(job_group)

        jobdata = self.SR.hget(prefix, jobid)
        if jobdata is None:
            return

        jobdata = json.loads(jobdata)
        status = jobdata.get('status', None)
        if status != 'RUNNING':
            LOG.info('Timeout for job {}-{} triggered but status not running'.format(prefix, jobid))
            return

        pid = jobdata.get('pid', None)
        if pid is None:
            LOG.error('Timeout for job {}-{} triggered but no pid available'.format(prefix, jobid))
            return

        LOG.error('Timeout for job {}-{} triggered, sending TERM signal'.format(prefix, jobid))
        os.kill(pid, signal.SIGTERM)

    def delete_job(self, job_group, jobid):
        prefix = REDIS_JOBS_GROUP_PREFIX.format(job_group)

        jobdata = self.SR.hget(prefix, jobid)
        if jobdata is None:
            return

        jobdata = json.loads(jobdata)

        logfile = jobdata.get('logfile', None)
        if logfile is not None:
            self._safe_remove(logfile)

        self._collect_job(jobdata)

        self.SR.hdel(prefix, jobid)

    def get_jobs(self, job_group):
        prefix = REDIS_JOBS_GROUP_PREFIX.format(job_group)
        result = {}

        jobs_map = self.SR.hgetall(prefix)

        for jobid, jobdata in jobs_map.iteritems():
            try:
                jobdata = json.loads(jobdata)

                if jobdata['status'] == 'RUNNING':
                    jobpid = jobdata['pid']
                    job_status = self._get_job_status(jobpid, jobdata['hash'])
                    jobdata.update(job_status)

                result[jobid] = jobdata

            except (ValueError, KeyError, psutil.ZombieProcess, psutil.AccessDenied):
                LOG.error('Invalid job value - deleting job {}::{}'.format(job_group, jobid))
                self.delete_job(job_group, jobid)
                continue

            if jobdata['status'] == 'DONE' and 'collected' not in jobdata:
                if jobid not in self.running_jobs[job_group]:
                    self._collect_job(jobdata)
                    self.SR.hset(job_group, jobid, json.dumps(jobdata))

        return result

    def exec_job(self, job_group, description, args, data=None, callback=None, timeout=None):
        jobid = str(uuid.uuid4())

        glet = gevent.spawn(
            self._job_monitor_glet,
            job_group, jobid, description, args, data
        )
        if callback is not None:
            glet.link(callback)

        timeout_glet = None
        if timeout is not None:
            timeout_glet = gevent.spawn(self._job_timeout_glet, job_group, jobid, timeout)

        self.running_jobs[job_group][jobid] = _Job(glet=glet, timeout_glet=timeout_glet)

        return jobid


def get_JobsManager():
    jobsmgr = getattr(g, '_jobs_manager', None)
    if jobsmgr is None:
        jobsmgr = JobsManager(connection_pool=REDIS_CP)
        g._jobs_manager = jobsmgr
    return jobsmgr


def teardown(exception):
    jobsmgr = getattr(g, '_jobs_manager', None)
    if jobsmgr is not None:
        g._jobs_manager = None
        LOG.info(
            'redis connection pool: in use: {} available: {}'.format(
                len(REDIS_CP._in_use_connections),
                len(REDIS_CP._available_connections)
            )
        )


JOBS_MANAGER = werkzeug.local.LocalProxy(get_JobsManager)


def init_app(app):
    app.teardown_appcontext(teardown)
