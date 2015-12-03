import jmespath
import logging
import antlr4
import operator

from .BoolExprParser import BoolExprParser  # noqa
from .BoolExprLexer import BoolExprLexer  # noqa
from .BoolExprListener import BoolExprListener  # noqa


LOG = logging.getLogger(__name__)


class _BECompiler(BoolExprListener):
    def exitExpression(self, ctx):
        self.expression = jmespath.compile(ctx.getText())

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


class Condition(object):
    def __init__(self, s):
        self.expression, self.comparator, self.value = self._parse_boolexpr(s)

    def _parse_boolexpr(self, s):
        lexer = BoolExprLexer(
            antlr4.InputStream(s)
        )
        stream = antlr4.CommonTokenStream(lexer)
        parser = BoolExprParser(stream)
        tree = parser.booleanExpression()

        eb = _BECompiler()
        walker = antlr4.ParseTreeWalker()
        walker.walk(eb, tree)

        return eb.expression, eb.comparator, eb.value

    def eval(self, i):
        try:
            r = self.expression.search(i)
        except jmespath.exceptions.JMESPathError:
            LOG.debug("Exception in eval: ", exc_info=True)
            r = None

        # XXX this is a workaround for a bug in JMESPath
        if r == 'null':
            r = None

        return self.comparator(r, self.value)
