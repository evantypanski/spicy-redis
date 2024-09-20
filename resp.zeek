type RESPData: record {
    simple_string: string &optional;
    simple_error: string &optional;
    i: int &optional;
    bulk_string: string &optional;
    #array:
    is_null: bool;
    boolean: bool &optional;
    #double_: double &optional;
    big_num: string &optional;
    bulk_error: string &optional;
    verbatim_string: string &optional;
};

event resp::data(c: connection, data: RESPData)
    {
    print "RESP data", c$id, data;
    }
