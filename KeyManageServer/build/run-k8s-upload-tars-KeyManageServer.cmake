EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo http://tars-tarsweb:3000/k8s/api/upload_tars_file -Fsuse=@KeyManageServer-merge.tars -Fapplication=Mitsurugi -Fserver_name=KeyManageServer)
EXECUTE_PROCESS(COMMAND curl http://tars-tarsweb:3000/k8s/api/upload_tars_file?ticket= -Fsuse=@KeyManageServer-merge.tars -Fapplication=Mitsurugi -Fserver_name=KeyManageServer)
EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo 
---------------------------------------------------------------------------)
