EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo http://web.tars.com/api/upload_and_publish -Fsuse=@KeyManageServer.tgz -Fapplication=Mitsurugi -Fmodule_name=KeyManageServer -Fcomment=developer-auto-upload)
EXECUTE_PROCESS(COMMAND curl http://web.tars.com/api/upload_and_publish?ticket= -Fsuse=@KeyManageServer.tgz -Fapplication=Mitsurugi -Fmodule_name=KeyManageServer -Fcomment=developer-auto-upload)
EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo 
---------------------------------------------------------------------------)
