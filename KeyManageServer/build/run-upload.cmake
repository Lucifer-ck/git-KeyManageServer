EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo upload all)
EXECUTE_PROCESS(COMMAND /usr/bin/cmake -P /home/lucifer/KeyManageServer/build/src/run-upload-KeyManageServer.cmake)
