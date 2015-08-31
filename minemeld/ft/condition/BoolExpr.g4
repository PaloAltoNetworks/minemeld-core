grammar BoolExpr;

@header {
# flake8: noqa
}

booleanExpression
    : expression comparator value
    ;

expression
    : JAVASCRIPTIDENTIFIER
    | functionExpression
    ;

functionExpression
    : JAVASCRIPTIDENTIFIER ( noArgs | oneOrMoreArgs )
    ;

noArgs
    : '(' ')'
    ;

oneOrMoreArgs
    : '(' expression (',' (expression|value))* ')'
    ;

JAVASCRIPTIDENTIFIER
    : [a-zA-Z_$][a-zA-Z_$0-9]*
    ;

comparator
    : '<'
    | '<='
    | '=='
    | '>='
    | '>'
    | '!='
    ;

value
    :   STRING
    |   NUMBER
    |   'true'
    |   'false'
    |   'null'
    ;

STRING 
    :  '"' (~["\\])* '"' 
    |  '\'' (~['\\])* '\'' 
    ;

NUMBER : '-'? INT ;

fragment INT :   '0' | [1-9] [0-9]* ; // no leading zeros

WS  :   [ \t\n\r]+ -> skip ;
