EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo upload k8s all)
EXECUTE_PROCESS(COMMAND cmake -P /home/lucifer/KeyManageServer/build/run-k8s-upload-KeyManageServer.cmake)
