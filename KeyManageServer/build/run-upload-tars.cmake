EXECUTE_PROCESS(COMMAND /usr/bin/cmake  -E echo upload tars all)
EXECUTE_PROCESS(COMMAND cmake -P /home/lucifer/KeyManageServer/build/src/run-upload-tars-KeyManageServer.cmake)
