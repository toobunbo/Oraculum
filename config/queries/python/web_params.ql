/**
 * @name Extract Web Request Parameters
 * @description Extracts parameter keys accessed via request.args, request.form, etc.
 * @kind table
 * @id py/extract/web-params
 */

import python

// Query 1: Tìm các lệnh gọi request.args.get('expr')
query predicate getMethodParams(string func, string file, string param, string src) {
  exists(Call call, Attribute attr, Name req, StrConst str |
    call.getFunc() = attr and
    attr.getObject() = req and
    req.getId() = "request" and
    attr.getName() in ["args", "form", "values", "json"] and
    call.getArg(0) = str and
    func = call.getEnclosingFunction().getName() and
    file = call.getEnclosingFunction().getLocation().getFile().getRelativePath() and
    param = str.getText() and
    src = attr.getName()
  )
}

// Query 2: Tìm các phép truy cập index request.args['expr']
query predicate getSubscriptParams(string func, string file, string param, string src) {
  exists(Subscript sub, Attribute attr, Name req, StrConst str |
    sub.getObject() = attr and
    attr.getObject() = req and
    req.getId() = "request" and
    attr.getName() in ["args", "form", "values"] and
    sub.getIndex() = str and
    func = sub.getEnclosingFunction().getName() and
    file = sub.getEnclosingFunction().getLocation().getFile().getRelativePath() and
    param = str.getText() and
    src = attr.getName()
  )
}

select func as function_name, file as file, param as param_name, src as source_type
from getMethodParams
union
select func as function_name, file as file, param as param_name, src as source_type
from getSubscriptParams
