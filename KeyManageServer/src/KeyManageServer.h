#ifndef _KeyManageServer_H_
#define _KeyManageServer_H_

#include <iostream>
#include "servant/Application.h"

using namespace tars;

/**
 *
 **/
class KeyManageServer : public Application
{
public:
    /**
     *
     **/
    virtual ~KeyManageServer() {};

    /**
     *
     **/
    virtual void initialize();

    /**
     *
     **/
    virtual void destroyApp();
};

extern KeyManageServer g_app;

////////////////////////////////////////////
#endif
