"""FT Table tests

Unit tests for minemeld.ft.boolexpr
"""

import unittest
import jmespath
import operator
import logging

import antlr4

import minemeld.ft.condition


LOG = logging.getLogger(__name__)


class ExprBuilder(minemeld.ft.condition.BoolExprListener):
    def __init__(self):
        self.expression = None
        self.comparator = None
        self.value = None

    def exitExpression(self, ctx):
        self.expression = ctx.getText()

    def exitComparator(self, ctx):
        comparator = ctx.getText()
        if comparator == '==':
            self.comparator = operator.eq
        elif comparator == '<':
            self.comparator = operator.lt
        elif comparator == '<=':
            self.comparator = operator.le
        elif comparator == '>':
            self.comparator = operator.gt
        elif comparator == '>=':
            self.comparator = operator.ge
        elif comparator == '!=':
            self.comparator = operator.ne

    def exitValue(self, ctx):
        if ctx.STRING() is not None:
            self.value = ctx.STRING().getText()[1:-1]
        elif ctx.NUMBER() is not None:
            self.value = int(ctx.NUMBER().getText())
        elif ctx.getText() == 'null':
            self.value = None
        elif ctx.getText() == 'false':
            self.value = False
        elif ctx.getText() == 'true':
            self.value = True


def _parse_string(s):
    lexer = minemeld.ft.condition.BoolExprLexer(
        antlr4.InputStream(s)
    )
    stream = antlr4.CommonTokenStream(lexer)
    parser = minemeld.ft.condition.BoolExprParser(stream)
    tree = parser.booleanExpression()

    eb = ExprBuilder()
    walker = antlr4.ParseTreeWalker()
    walker.walk(eb, tree)

    return eb


def _eval_expression(eb, i):
    ce = jmespath.compile(eb.expression)

    try:
        r = ce.search(i)
    except jmespath.exceptions.JMESPathError:
        LOG.exception("Exception in searching")
        r = None

    LOG.info("r: %s value: %s", r, eb.value)

    return eb.comparator(r, eb.value)


class MineMeldFTBaseTests(unittest.TestCase):
    def test_simple(self):
        eb = _parse_string('sources == "http://dshield.org/blocklist"')
        self.assertEqual(eb.expression, u'sources')
        self.assertEqual(eb.comparator, operator.eq)
        self.assertEqual(eb.value, 'http://dshield.org/blocklist')

    def test_func(self):
        eb = _parse_string('length(max(dshield_nattacks)) == '
                           '"http://dshield.org/blocklist"')
        self.assertEqual(eb.expression, u'length(max(dshield_nattacks))')
        self.assertEqual(eb.comparator, operator.eq)
        self.assertEqual(eb.value, 'http://dshield.org/blocklist')

    def test_eval(self):
        i = {
            'sources': [1, 2],
            'type': 'IPv4'
        }

        c = minemeld.ft.condition.Condition('length(sources) > 1')
        self.assertTrue(c.eval(i))

        c = minemeld.ft.condition.Condition('length(b) > 1')
        self.assertFalse(c.eval(i))

        c = minemeld.ft.condition.Condition('type(b) == null')
        self.assertTrue(c.eval(i))

        c = minemeld.ft.condition.Condition('length(b) == null')
        self.assertTrue(c.eval(i))

        c = minemeld.ft.condition.Condition("starts_with(type, 'IP') "
                                              "== true")
        self.assertTrue(c.eval(i))

        c = minemeld.ft.condition.Condition("type == 'IPv4'")
        self.assertTrue(c.eval(i))
