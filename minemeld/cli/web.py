from init import setup
from minemeld.flask.main import app

if __name__ == '__main__':
    setup()
    app.run(threaded=True, passthrough_errors=False)
