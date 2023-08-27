EXECUTE_PROCESS(COMMAND /usr/bin/cmake  -E echo upload k8s tars all)
EXECUTE_PROCESS(COMMAND cmake -P /home/lucifer/KeyManageServer/build/run-k8s-upload-tars-KeyManageServer.cmake)
