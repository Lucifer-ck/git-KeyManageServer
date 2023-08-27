EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo http://tars-tarsweb:3000/pages/k8s/api/upload_and_publish -Fsuse=@KeyManageServer.tgz -Fapplication=Mitsurugi -Fmodule_name=KeyManageServer -Fserver_type=cpp -Fbase_image=tarscloud/tars.cppbase -Fcomment=developer-auto-upload)
EXECUTE_PROCESS(COMMAND curl http://tars-tarsweb:3000/pages/k8s/api/upload_and_publish?ticket= -Fsuse=@KeyManageServer.tgz -Fapplication=Mitsurugi -Fmodule_name=KeyManageServer -Fserver_type=cpp  -Fbase_image=tarscloud/tars.cppbase -Fcomment=developer-auto-upload)
EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo 
---------------------------------------------------------------------------)
