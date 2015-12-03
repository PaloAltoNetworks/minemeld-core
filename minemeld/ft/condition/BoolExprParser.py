# Generated from BoolExpr.g4 by ANTLR 4.5.1
# encoding: utf-8
from __future__ import print_function
from antlr4 import *
from io import StringIO


# flake8: noqa

def serializedATN():
    with StringIO() as buf:
        buf.write(u"\3\u0430\ud6d1\u8206\uad2d\u4417\uaef1\u8d80\uaadd\3")
        buf.write(u"\22\63\4\2\t\2\4\3\t\3\4\4\t\4\4\5\t\5\4\6\t\6\4\7\t")
        buf.write(u"\7\4\b\t\b\3\2\3\2\3\2\3\2\3\3\3\3\5\3\27\n\3\3\4\3\4")
        buf.write(u"\3\4\5\4\34\n\4\3\5\3\5\3\5\3\6\3\6\3\6\3\6\3\6\5\6&")
        buf.write(u"\n\6\7\6(\n\6\f\6\16\6+\13\6\3\6\3\6\3\7\3\7\3\b\3\b")
        buf.write(u"\3\b\2\2\t\2\4\6\b\n\f\16\2\4\3\2\6\13\4\2\f\16\20\21")
        buf.write(u"/\2\20\3\2\2\2\4\26\3\2\2\2\6\30\3\2\2\2\b\35\3\2\2\2")
        buf.write(u"\n \3\2\2\2\f.\3\2\2\2\16\60\3\2\2\2\20\21\5\4\3\2\21")
        buf.write(u"\22\5\f\7\2\22\23\5\16\b\2\23\3\3\2\2\2\24\27\7\17\2")
        buf.write(u"\2\25\27\5\6\4\2\26\24\3\2\2\2\26\25\3\2\2\2\27\5\3\2")
        buf.write(u"\2\2\30\33\7\17\2\2\31\34\5\b\5\2\32\34\5\n\6\2\33\31")
        buf.write(u"\3\2\2\2\33\32\3\2\2\2\34\7\3\2\2\2\35\36\7\3\2\2\36")
        buf.write(u"\37\7\4\2\2\37\t\3\2\2\2 !\7\3\2\2!)\5\4\3\2\"%\7\5\2")
        buf.write(u"\2#&\5\4\3\2$&\5\16\b\2%#\3\2\2\2%$\3\2\2\2&(\3\2\2\2")
        buf.write(u"\'\"\3\2\2\2(+\3\2\2\2)\'\3\2\2\2)*\3\2\2\2*,\3\2\2\2")
        buf.write(u"+)\3\2\2\2,-\7\4\2\2-\13\3\2\2\2./\t\2\2\2/\r\3\2\2\2")
        buf.write(u"\60\61\t\3\2\2\61\17\3\2\2\2\6\26\33%)")
        return buf.getvalue()


class BoolExprParser ( Parser ):

    grammarFileName = "BoolExpr.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ u"<INVALID>", u"'('", u"')'", u"','", u"'<'", u"'<='", 
                     u"'=='", u"'>='", u"'>'", u"'!='", u"'true'", u"'false'", 
                     u"'null'" ]

    symbolicNames = [ u"<INVALID>", u"<INVALID>", u"<INVALID>", u"<INVALID>", 
                      u"<INVALID>", u"<INVALID>", u"<INVALID>", u"<INVALID>", 
                      u"<INVALID>", u"<INVALID>", u"<INVALID>", u"<INVALID>", 
                      u"<INVALID>", u"JAVASCRIPTIDENTIFIER", u"STRING", 
                      u"NUMBER", u"WS" ]

    RULE_booleanExpression = 0
    RULE_expression = 1
    RULE_functionExpression = 2
    RULE_noArgs = 3
    RULE_oneOrMoreArgs = 4
    RULE_comparator = 5
    RULE_value = 6

    ruleNames =  [ u"booleanExpression", u"expression", u"functionExpression", 
                   u"noArgs", u"oneOrMoreArgs", u"comparator", u"value" ]

    EOF = Token.EOF
    T__0=1
    T__1=2
    T__2=3
    T__3=4
    T__4=5
    T__5=6
    T__6=7
    T__7=8
    T__8=9
    T__9=10
    T__10=11
    T__11=12
    JAVASCRIPTIDENTIFIER=13
    STRING=14
    NUMBER=15
    WS=16

    def __init__(self, input):
        super(BoolExprParser, self).__init__(input)
        self.checkVersion("4.5.1")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None



    class BooleanExpressionContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.BooleanExpressionContext, self).__init__(parent, invokingState)
            self.parser = parser

        def expression(self):
            return self.getTypedRuleContext(BoolExprParser.ExpressionContext,0)


        def comparator(self):
            return self.getTypedRuleContext(BoolExprParser.ComparatorContext,0)


        def value(self):
            return self.getTypedRuleContext(BoolExprParser.ValueContext,0)


        def getRuleIndex(self):
            return BoolExprParser.RULE_booleanExpression

        def enterRule(self, listener):
            if hasattr(listener, "enterBooleanExpression"):
                listener.enterBooleanExpression(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitBooleanExpression"):
                listener.exitBooleanExpression(self)




    def booleanExpression(self):

        localctx = BoolExprParser.BooleanExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_booleanExpression)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 14
            self.expression()
            self.state = 15
            self.comparator()
            self.state = 16
            self.value()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class ExpressionContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.ExpressionContext, self).__init__(parent, invokingState)
            self.parser = parser

        def JAVASCRIPTIDENTIFIER(self):
            return self.getToken(BoolExprParser.JAVASCRIPTIDENTIFIER, 0)

        def functionExpression(self):
            return self.getTypedRuleContext(BoolExprParser.FunctionExpressionContext,0)


        def getRuleIndex(self):
            return BoolExprParser.RULE_expression

        def enterRule(self, listener):
            if hasattr(listener, "enterExpression"):
                listener.enterExpression(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitExpression"):
                listener.exitExpression(self)




    def expression(self):

        localctx = BoolExprParser.ExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_expression)
        try:
            self.state = 20
            la_ = self._interp.adaptivePredict(self._input,0,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 18
                self.match(BoolExprParser.JAVASCRIPTIDENTIFIER)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 19
                self.functionExpression()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class FunctionExpressionContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.FunctionExpressionContext, self).__init__(parent, invokingState)
            self.parser = parser

        def JAVASCRIPTIDENTIFIER(self):
            return self.getToken(BoolExprParser.JAVASCRIPTIDENTIFIER, 0)

        def noArgs(self):
            return self.getTypedRuleContext(BoolExprParser.NoArgsContext,0)


        def oneOrMoreArgs(self):
            return self.getTypedRuleContext(BoolExprParser.OneOrMoreArgsContext,0)


        def getRuleIndex(self):
            return BoolExprParser.RULE_functionExpression

        def enterRule(self, listener):
            if hasattr(listener, "enterFunctionExpression"):
                listener.enterFunctionExpression(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitFunctionExpression"):
                listener.exitFunctionExpression(self)




    def functionExpression(self):

        localctx = BoolExprParser.FunctionExpressionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_functionExpression)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 22
            self.match(BoolExprParser.JAVASCRIPTIDENTIFIER)
            self.state = 25
            la_ = self._interp.adaptivePredict(self._input,1,self._ctx)
            if la_ == 1:
                self.state = 23
                self.noArgs()
                pass

            elif la_ == 2:
                self.state = 24
                self.oneOrMoreArgs()
                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class NoArgsContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.NoArgsContext, self).__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return BoolExprParser.RULE_noArgs

        def enterRule(self, listener):
            if hasattr(listener, "enterNoArgs"):
                listener.enterNoArgs(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitNoArgs"):
                listener.exitNoArgs(self)




    def noArgs(self):

        localctx = BoolExprParser.NoArgsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_noArgs)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 27
            self.match(BoolExprParser.T__0)
            self.state = 28
            self.match(BoolExprParser.T__1)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class OneOrMoreArgsContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.OneOrMoreArgsContext, self).__init__(parent, invokingState)
            self.parser = parser

        def expression(self, i=None):
            if i is None:
                return self.getTypedRuleContexts(BoolExprParser.ExpressionContext)
            else:
                return self.getTypedRuleContext(BoolExprParser.ExpressionContext,i)


        def value(self, i=None):
            if i is None:
                return self.getTypedRuleContexts(BoolExprParser.ValueContext)
            else:
                return self.getTypedRuleContext(BoolExprParser.ValueContext,i)


        def getRuleIndex(self):
            return BoolExprParser.RULE_oneOrMoreArgs

        def enterRule(self, listener):
            if hasattr(listener, "enterOneOrMoreArgs"):
                listener.enterOneOrMoreArgs(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitOneOrMoreArgs"):
                listener.exitOneOrMoreArgs(self)




    def oneOrMoreArgs(self):

        localctx = BoolExprParser.OneOrMoreArgsContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_oneOrMoreArgs)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 30
            self.match(BoolExprParser.T__0)
            self.state = 31
            self.expression()
            self.state = 39
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==BoolExprParser.T__2:
                self.state = 32
                self.match(BoolExprParser.T__2)
                self.state = 35
                token = self._input.LA(1)
                if token in [BoolExprParser.JAVASCRIPTIDENTIFIER]:
                    self.state = 33
                    self.expression()

                elif token in [BoolExprParser.T__9, BoolExprParser.T__10, BoolExprParser.T__11, BoolExprParser.STRING, BoolExprParser.NUMBER]:
                    self.state = 34
                    self.value()

                else:
                    raise NoViableAltException(self)

                self.state = 41
                self._errHandler.sync(self)
                _la = self._input.LA(1)

            self.state = 42
            self.match(BoolExprParser.T__1)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class ComparatorContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.ComparatorContext, self).__init__(parent, invokingState)
            self.parser = parser


        def getRuleIndex(self):
            return BoolExprParser.RULE_comparator

        def enterRule(self, listener):
            if hasattr(listener, "enterComparator"):
                listener.enterComparator(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitComparator"):
                listener.exitComparator(self)




    def comparator(self):

        localctx = BoolExprParser.ComparatorContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_comparator)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 44
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << BoolExprParser.T__3) | (1 << BoolExprParser.T__4) | (1 << BoolExprParser.T__5) | (1 << BoolExprParser.T__6) | (1 << BoolExprParser.T__7) | (1 << BoolExprParser.T__8))) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx

    class ValueContext(ParserRuleContext):

        def __init__(self, parser, parent=None, invokingState=-1):
            super(BoolExprParser.ValueContext, self).__init__(parent, invokingState)
            self.parser = parser

        def STRING(self):
            return self.getToken(BoolExprParser.STRING, 0)

        def NUMBER(self):
            return self.getToken(BoolExprParser.NUMBER, 0)

        def getRuleIndex(self):
            return BoolExprParser.RULE_value

        def enterRule(self, listener):
            if hasattr(listener, "enterValue"):
                listener.enterValue(self)

        def exitRule(self, listener):
            if hasattr(listener, "exitValue"):
                listener.exitValue(self)




    def value(self):

        localctx = BoolExprParser.ValueContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_value)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 46
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << BoolExprParser.T__9) | (1 << BoolExprParser.T__10) | (1 << BoolExprParser.T__11) | (1 << BoolExprParser.STRING) | (1 << BoolExprParser.NUMBER))) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





