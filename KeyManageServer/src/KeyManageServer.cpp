#include "KeyManageServer.h"
#include "KeyManageImp.h"

using namespace std;

KeyManageServer g_app;

/////////////////////////////////////////////////////////////////
void
KeyManageServer::initialize()
{
    //initialize application here:
    //...

    addServant<KeyManageImp>(ServerConfig::Application + "." + ServerConfig::ServerName + ".KeyManageObj");
}
/////////////////////////////////////////////////////////////////
void
KeyManageServer::destroyApp()
{
    //destroy application here:
    //...
}
/////////////////////////////////////////////////////////////////
int
main(int argc, char* argv[])
{
    try
    {
        g_app.main(argc, argv);
        g_app.waitForShutdown();
    }
    catch (std::exception& e)
    {
        cerr << "std::exception:" << e.what() << std::endl;
    }
    catch (...)
    {
        cerr << "unknown exception." << std::endl;
    }
    return -1;
}
/////////////////////////////////////////////////////////////////
