EXECUTE_PROCESS(COMMAND /usr/bin/cmake -E echo release all)
EXECUTE_PROCESS(COMMAND /usr/bin/cmake -P /home/lucifer/KeyManageServer/build/src/run-release-KeyManageServer.cmake)
