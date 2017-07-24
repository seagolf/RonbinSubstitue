#include <string>
#include <iostream>
#include <fstream>
#include <list>
#include <vector>
#include <algorithm>
#include <chrono>


#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>
#include <sys/stat.h>

#include "tinyxml2.h"

using namespace std;
using namespace std::chrono;
using namespace tinyxml2;

typedef struct
{
    string portId;
    string protocol;
    string serviceName;
    string status;

}PortInfoT;


typedef struct 
{
    string apMacAddr;
    string devMacAddr;
    string hostName;
    string hostType;
    string hostOs;
    string vendor;
    string ipAddr;
    vector <PortInfoT> portInfo;
    string scanTs;
}ScanInfoT;

typedef struct 
{
  char *memory;
  size_t size;
}MemoryStruct;

bool getWanIpStub( string &wanIp)
{
    wanIp = "66.131.226.178";
    return true;

}

bool HandleQueryResponse(MemoryStruct getResponse)
{
    bool needPopBack = false;

#ifdef DEBUG
    cout << getResponse.memory << endl;
#endif

    string response (getResponse.memory);

    string typeString = "\"deviceType\"";
    string devMacString ="\"deviceMacAddr\"";
    list <string> whiteList;
    list <string> grepList;
    list <string> blackList;
    while (!response.empty())
    {
        int typePos = 0;
        int devMacPos = 0;
        string devMac;
        char type;

        bool toWhiteList = false;
        bool toGrepList = false;
        typePos  = response.find(typeString.c_str());
        if( typePos == string::npos)
        {
            break;
        }
        typePos += typeString.length() + 1; //1 for ':'  
        type = response.at(typePos);

        string subEntry = response.substr(0, typePos);

        devMacPos = subEntry.find(devMacString.c_str());
        devMacPos += devMacString.length() + 2; // 1 for '0', 1 for '"'

        devMac = subEntry.substr(devMacPos, 17); // 2*6+5, 2*6 stands for 00, 5 stands for ':'

        switch (type)
        {
            //IOT
            case '3':
                cout << "insert iot device: " << devMac  << " to white list"<< endl;

                toWhiteList = true;
                break;
            case '1': //computer
            case '2': //mobile
            case '4': //camera
            case '5': //others
                cout << "insert device: " << devMac << "to grep list" << endl;
                toGrepList = true;
                break;
            default :
                cout << "device type" << type <<  endl;
                cout << "not supported device type" << endl;
                break;

        
        }
        
        
        if (toWhiteList)
        {

            if (find(whiteList.begin(), whiteList.end(), devMac.c_str()) != whiteList.end())
            {
                cout << "device " << devMac << "already in the list" <<endl; 
            }

            else
            {
                cout << " add device " << devMac << " to the list done" << endl;
                whiteList.push_back(devMac);

            }
        }
        
        else if (toGrepList)
        {

            if (find(grepList.begin(), grepList.end(), devMac.c_str()) != grepList.end())
            {
                cout << "device " << devMac << "already in the list" <<endl; 
            }

            else
            {
                cout << " add device " << devMac << " to the list done" << endl;
                grepList.push_back(devMac);

            }
        }
        
        response.erase(0,typePos+1);

    }

    ofstream deviceListConf("/var/www/device-list.conf");

    if(!deviceListConf.is_open())
    {
        cout << "faild to create /var/www/device-list.conf" << endl;
        return false;
    }

    string whiteListString = "white_list_mac=";
    string grepListString = "grep_list_mac=";
    string blackListString ="black_list_mac=";
    for(list<string>::iterator it = whiteList.begin(); it != whiteList.end(); it++)
    {
        whiteListString += *it;
        whiteListString += ",";
        needPopBack = true;
    }

    if(needPopBack)
    {
        whiteListString.pop_back();
        needPopBack = false;
    }

    for(list<string>::iterator it = grepList.begin(); it != grepList.end(); it++)
    {
        grepListString += *it;
        grepListString += ",";
        needPopBack = true;
    }

    if(needPopBack)
    {
        grepListString.pop_back();
        needPopBack = false;
    }

    for(list<string>::iterator it = blackList.begin(); it != blackList.end(); it++)
    {
        blackListString += *it;
        blackListString += ",";
        needPopBack = true;
    }

    if(needPopBack)
    {
        blackListString.pop_back();
        needPopBack = false;
    }

    deviceListConf << whiteListString;
    deviceListConf << endl;
    deviceListConf << grepListString;
    deviceListConf << endl;
    deviceListConf << blackListString;
    deviceListConf << endl;

    deviceListConf.close();
    
    return true;


}


static
size_t DeviceTypeCallback(void *contents, size_t size, size_t nmemb, void *userp)                                                                        
{
  size_t realsize = size * nmemb;
  MemoryStruct *mem = (MemoryStruct *)userp;

  mem->memory = (char *) realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
      }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}


int main(int argc, char *argv[])
{
    vector <ScanInfoT> inScanInfo;
    vector <ScanInfoT> exScanInfo;

    string gApMac;
    string wanIp; 

    getWanIpStub(wanIp);
        

    if ( argc < 3 )
    {
        //cout << " please  input GW ip: " << endl;
        cout << "Usage: register <ip addr> <inner xml file1> <external xml file> " << endl;
        return -1;
    }

    string apIpAddr(argv[1]);
    string apMacAddr;
    bool bInScan = false;
    bool bExScan = false;

    string usrRegJsonObj;
    string devRegJsonObj ("["); 
    string devSrvRegJsonObj ("[");
    string pubSrvRegJsonObj ("[");
    //parse xml
    if(strstr(argv[2], "in") == NULL || strstr (argv[3], "ex") == NULL)
    {
        cout << "Usage: register <ip addr> <inner xml file1> <external xml file> " << endl;
        return -1; 
    
    }
    

    for (int argvOffset=2; argvOffset < 4; argvOffset++)
    {
        if (strstr(argv[argvOffset], "in" ) != NULL)
        {
            bInScan = true;
            bExScan = false;
        }
        else if ( strstr (argv[argvOffset], "ex") !=NULL)
        {
            bExScan = true;
            bInScan = false;
            
        }

        else
        {
            cout << "wrong xml file input" << endl;
            cout << "there should be 'in' for inner scan xml, and 'ex' for external scan xml" << endl;
            return -1;
        }


        // Open the file and read it into a vector
        std::ifstream ifs(argv[argvOffset], std::ios::in | std::ios::binary | std::ios::ate);
        std::ifstream::pos_type fsize = ifs.tellg();
        ifs.seekg(0, ios::beg);
        std::vector<char> bytes(fsize);
        ifs.read(&bytes[0], fsize);

        // Create string from vector
        std::string xml_str(&bytes[0], fsize);

        // Skip unsupported statements
        size_t pos = 0;
        while (true) 
        {
            pos = xml_str.find_first_of("<", pos);
            if (xml_str[pos + 1] == '?' || // <?xml...
                    xml_str[pos + 1] == '!') 
            { // <!DOCTYPE... or [<!ENTITY...
                // Skip this line
                pos = xml_str.find_first_of("\n", pos);
            } else
                break;
        }
        xml_str = xml_str.substr(pos);

        XMLDocument doc;
        if(doc.Parse(xml_str.c_str()))
        {
            cout << "Failed: open xml file " << argv[argvOffset] << endl;
            return false;
        }

        XMLElement *root = doc.FirstChildElement();

        if (root == NULL)
        {

            cerr << "Failed to load xml file: No root element" << endl;
            return false;

        }


        int i = 0;
        vector <ScanInfoT> scanInfo;
        
        for (XMLElement *elem = root->FirstChildElement("host"); elem !=NULL;
                elem = elem->NextSiblingElement("host"), i++)
        {


            const char * macAddr = NULL;
            const char * ipAddr = NULL;
            const char * hostOs = NULL;
            const char * hostType = NULL;
            const char * hostName = NULL;
            const char * vendor = NULL;

            ScanInfoT hostInfo;

            const char * scanTs = elem->Attribute("starttime");
            if ( scanTs != NULL)
            {
                hostInfo.scanTs = scanTs;
            }

            for (XMLElement *addrElem = elem->FirstChildElement("address"); addrElem != NULL;
                    addrElem = addrElem->NextSiblingElement("address"))
            {



                const char * addrType = addrElem->Attribute("addrtype");
                if (addrType == NULL)
                {
                    cout << "cannot find addrType" << endl;
                    continue;

                }

                if ( strcmp(addrType, "ipv4") == 0)
                {

                    ipAddr = addrElem->Attribute("addr");
                    if( ipAddr != NULL) 
                    {
#ifdef DEBUG
                        {
                            cout << "ip addres:  " << ipAddr<< endl;
                        }
#endif
                        hostInfo.ipAddr = ipAddr;

                    }
                }

                else if(strcmp(addrType, "mac") == 0)
                {

                    macAddr = addrElem->Attribute("addr");

#ifdef DEBUG
                    {
                        cout << "mac addres " << macAddr << endl;
                    }
#endif
                    hostInfo.devMacAddr = macAddr;

                    vendor = addrElem->Attribute("vendor");

                    hostInfo.vendor = vendor;

#ifdef DEBUG
                    {
                        cout << "vendor : " << vendor << endl;;
                    }
#endif
                }

                else
                {

                    {
                        cout << "not supported addrtype :" << addrElem->Attribute("addrtype")  <<endl;
                    }
                }

            }


            //determin apMac
            if (strcmp(hostInfo.ipAddr.c_str(), argv[1]) == 0)
            {
                gApMac = hostInfo.devMacAddr;
            }


            //curl





            XMLElement * hostNamesElem = elem->FirstChildElement("hostnames");
            if (hostNamesElem != NULL)
            {

                XMLElement * hostNameElem = hostNamesElem-> FirstChildElement("hostname");
                if (hostNameElem != NULL)
                {

                    hostName = hostNameElem->Attribute("name");
                    hostType = hostNameElem->Attribute("type");
                }
            }


            for (XMLElement *portElem = elem->FirstChildElement("ports")->FirstChildElement("port"); portElem != NULL;
                    portElem = portElem->NextSiblingElement("port"))
            {

                PortInfoT tmpPortInfo;

                const char * protocol  = portElem->Attribute("protocol");
                if (protocol  != NULL)
                {
                    tmpPortInfo.protocol = protocol;

                }

                const char * portId = portElem->Attribute("portid");
                if (portId != NULL)
                {
                    tmpPortInfo.portId = portId;

                }

                const char * status = portElem->FirstChildElement("state")->Attribute("state");
                if (status != NULL)
                {

                    tmpPortInfo.status = status;
                }

                const char * serviceName = portElem->FirstChildElement("service")->Attribute("name");
                if (serviceName != NULL)
                {

                    tmpPortInfo.serviceName = serviceName;
                }


                hostInfo.portInfo.push_back(tmpPortInfo);


            }

            XMLElement * hostOsElem = elem->FirstChildElement("os");

            if (hostOsElem != NULL)
            {

                XMLElement * hostOsMatchElem = hostOsElem->FirstChildElement("osmatch");                                         
                if (hostOsMatchElem != NULL)
                {
                    hostOs = hostOsMatchElem->Attribute("name");
                }
            } 


            scanInfo.push_back(hostInfo); 

        }
        
        if(bInScan)
        {
            inScanInfo = scanInfo;
        
        }
        else
        {
            exScanInfo = scanInfo;
        }



        if( bInScan)
        {
            usrRegJsonObj = "{\"userId\":\"";
            //usrRegJsonObj.append(userName);
            usrRegJsonObj.append("hzspec7");
            usrRegJsonObj.append("\",");
            usrRegJsonObj.append("\"password\":\"123456\",\"phoneNumber\":\"13812345678\",\"emailAddr\":\"nobody1@hzspec.com\",\"apMacAddr\":\"");
            usrRegJsonObj.append(gApMac);
            usrRegJsonObj.append("\",");
            usrRegJsonObj.append("\"ip\":\"");
            usrRegJsonObj.append(wanIp);
            usrRegJsonObj.append("\"}");

            //devRegJsonObj.append ("[");
            for ( vector<ScanInfoT>::iterator it = inScanInfo.begin(); it !=inScanInfo.end(); it++)
            {

                ScanInfoT tmpInfo = *it;

                {
                    devRegJsonObj.append("{\"apMacAddr\": \"");
                    devRegJsonObj.append (gApMac);
                    devRegJsonObj.append ("\","); 

                    devRegJsonObj.append ("\"deviceMacAddr\": \"");
                    if(!tmpInfo.devMacAddr.empty())
                        devRegJsonObj.append (tmpInfo.devMacAddr);
                    else
                        devRegJsonObj.append (gApMac);

                    devRegJsonObj.append ("\",");

                    devRegJsonObj.append ("\"ip\": \"");
                    if(!tmpInfo.ipAddr.empty())
                        devRegJsonObj.append (tmpInfo.ipAddr);
                    else
                        devRegJsonObj.append ("unknown");
                    devRegJsonObj.append ("\",");

                    devRegJsonObj.append ("\"os\":\"");
                    if (!tmpInfo.hostOs.empty())
                        devRegJsonObj.append (tmpInfo.hostOs);
                    else 
                        devRegJsonObj.append ("unknown");
                    devRegJsonObj.append ("\",");

                    devRegJsonObj.append ("\"vendor\":\"");
                    if (!tmpInfo.vendor.empty())
                        devRegJsonObj.append (tmpInfo.vendor);
                    else 
                        devRegJsonObj.append ("unknown");
                    devRegJsonObj.append ("\"},");
                }

                for ( vector <PortInfoT>::iterator itPort = tmpInfo.portInfo.begin(); itPort != tmpInfo.portInfo.end(); itPort++)
                {


                    PortInfoT tmpPortInfo = *itPort;
#ifdef DEBUG
                    cout << "    ip "        << tmpInfo.ipAddr << endl;
                    cout << "    apMacAddr: "   << gApMac << endl;   
                    cout << "    devMacAddr: "  << tmpInfo.devMacAddr << endl;
                    cout << "    hostname:  "   << tmpInfo.hostName << endl;
                    cout << "    hostType:  "   << tmpInfo.hostType << endl;
                    cout << "    hostOs:    "   << tmpInfo.hostOs << endl;
                    cout << "    vendor:    "   << tmpInfo.vendor << endl;
                    cout << "    scan timestamp: " << tmpInfo.scanTs << endl;

                    cout << "    port: "        << tmpPortInfo.portId << endl;
                    cout << "    protocol:  "   << tmpPortInfo.protocol << endl;
                    cout << "    service: "     << tmpPortInfo.serviceName << endl;
                    cout << "    status: "      << tmpPortInfo.status << endl;
#endif

                    devSrvRegJsonObj.append("{\"apMacAddr\": \"");

                    devSrvRegJsonObj.append (gApMac);
                    devSrvRegJsonObj.append ("\","); 

                
                    devSrvRegJsonObj.append ("\"deviceMacAddr\": \"");
                    if (!tmpInfo.devMacAddr.empty())
                        devSrvRegJsonObj.append (tmpInfo.devMacAddr);
                    else
                        devSrvRegJsonObj.append (gApMac);

                    devSrvRegJsonObj.append ("\",");


                    devSrvRegJsonObj.append ("\"ip\": \"");
                    devSrvRegJsonObj.append (tmpInfo.ipAddr);
                    devSrvRegJsonObj.append ("\",");

                    devSrvRegJsonObj.append ("\"port\": ");
                    devSrvRegJsonObj.append (tmpPortInfo.portId);
                    devSrvRegJsonObj.append (",");

                    devSrvRegJsonObj.append ("\"protocol\": \"");
                    devSrvRegJsonObj.append (tmpPortInfo.protocol);
                    devSrvRegJsonObj.append ("\",");

                    devSrvRegJsonObj.append ("\"service\": \"");
                    devSrvRegJsonObj.append (tmpPortInfo.serviceName);
                    devSrvRegJsonObj.append ("\",");

                    devSrvRegJsonObj.append ("\"status\": \"");
                    devSrvRegJsonObj.append (tmpPortInfo.status);
                    devSrvRegJsonObj.append ("\"},");
                }
            }
            devSrvRegJsonObj.pop_back();
            devSrvRegJsonObj.append ("]");


            devRegJsonObj.pop_back();
            devRegJsonObj.append("]");
        }

        else if (bExScan)
        {
        
            for ( vector<ScanInfoT>::iterator it = exScanInfo.begin(); it !=exScanInfo.end(); it++)
            {

                ScanInfoT tmpInfo = *it;

                for ( vector <PortInfoT>::iterator itPort = tmpInfo.portInfo.begin(); itPort != tmpInfo.portInfo.end(); itPort++)
                {


                    PortInfoT tmpPortInfo = *itPort;
#ifdef DEBUG
                    cout << "    ip "        << tmpInfo.ipAddr << endl;
                    cout << "    apMacAddr: "   << gApMac << endl;   
                    cout << "    devMacAddr: "  << tmpInfo.devMacAddr << endl;
                    cout << "    hostname:  "   << tmpInfo.hostName << endl;
                    cout << "    hostType:  "   << tmpInfo.hostType << endl;
                    cout << "    hostOs:    "   << tmpInfo.hostOs << endl;
                    cout << "    vendor:    "   << tmpInfo.vendor << endl;
                    cout << "    scan timestamp: " << tmpInfo.scanTs << endl;

                    cout << "    port: "        << tmpPortInfo.portId << endl;
                    cout << "    protocol:  "   << tmpPortInfo.protocol << endl;
                    cout << "    service: "     << tmpPortInfo.serviceName << endl;
                    cout << "    status: "      << tmpPortInfo.status << endl;
#endif

                    pubSrvRegJsonObj.append("{\"apMacAddr\": \"");
                    pubSrvRegJsonObj.append (gApMac);
                    pubSrvRegJsonObj.append ("\","); 


                    //pubSrvRegJsonObj.append ("\"ip\": \"");
                    //pubSrvRegJsonObj.append (tmpInfo.ipAddr);
                    //pubSrvRegJsonObj.append ("\",");

                    pubSrvRegJsonObj.append ("\"port\": \"");
                    pubSrvRegJsonObj.append (tmpPortInfo.portId);
                    pubSrvRegJsonObj.append ("\",");

                    pubSrvRegJsonObj.append ("\"protocol\": \"");
                    pubSrvRegJsonObj.append (tmpPortInfo.protocol);
                    pubSrvRegJsonObj.append ("\",");

                    pubSrvRegJsonObj.append ("\"service\": \"");
                    pubSrvRegJsonObj.append (tmpPortInfo.serviceName);
                    pubSrvRegJsonObj.append ("\",");

                    pubSrvRegJsonObj.append ("\"userId\": \"hzspec7\",");

                    pubSrvRegJsonObj.append ("\"status\": \"");
                    pubSrvRegJsonObj.append (tmpPortInfo.status);
                    //pubSrvRegJsonObj.append ("1");
                    pubSrvRegJsonObj.append ("\"},");
                }
            }

            pubSrvRegJsonObj.pop_back();
            pubSrvRegJsonObj.append ("]");
        
        }

    }
        CURL *pCurl;
        CURLcode res;

        pCurl = curl_easy_init();
        struct curl_slist *headers = NULL;
        //register

        if (NULL == pCurl)
        {   
            cout << "faile to init curl" << endl;
            return false;
        }


        cout << "register users" << endl;
        string usrRegUrl = "http://60.205.212.99/squirrel/v1/users";
        //regiseter {user,ApMacAddr}



        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(pCurl, CURLOPT_URL, usrRegUrl.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, usrRegJsonObj.c_str()); 


        //some servers don't like requests that are made without a user-agent field, so we provide one  
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(pCurl);

        // check for errors
        if(res != CURLE_OK)
        {
            cout<<"ERROR: curl_easy_perform failed" << curl_easy_strerror(res) << endl;
        }
        else
        {
            //Now, our chunk.memory points to a memory block that is chunk.size
            //bytes big and contains the remote file.

            if(CURLE_OK == res)
            {
                long response_code;

                curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &response_code);

                if( response_code != 200)
                {
                    cout <<" Error! "  << endl;
                }
                cout <<"  response code: "  << (int) response_code << endl;
                
#if 0

                char *ct;
                //ask for the content-type  
                res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                if((CURLE_OK == res) && ct)
                {
                    {
                        cout << "We received Content-Type:" <<  ct <<endl;
                    }
                }
#endif
            }
        }

        curl_easy_cleanup(pCurl);


        pCurl = curl_easy_init();

        //register devices
        cout << "register devices_to_usr" << endl;

        string devRegUrl= "http://60.205.212.99/squirrel/v1/devices/add_devices_to_user";
        
        headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(pCurl, CURLOPT_URL, devRegUrl.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, devRegJsonObj.c_str()); 


        //some servers don't like requests that are made without a user-agent field, so we provide one  
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(pCurl);

        // check for errors
        if(res != CURLE_OK)
        {
            cout<<"ERROR: curl_easy_perform failed" << curl_easy_strerror(res) << endl;
        }
        else
        {
            //Now, our chunk.memory points to a memory block that is chunk.size
            //bytes big and contains the remote file.

            if(CURLE_OK == res)
            {
                long response_code;

                curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &response_code);

                if( response_code != 200)
                {
                    cout <<" Error! response code:"  << (int) response_code << endl;
                }
                else
                {
                    cout << "response code :200" <<endl;
                }

#if 0
                char *ct;
                //ask for the content-type  
                res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                if((CURLE_OK == res) && ct)
                {
                    {
                        cout << "We received Content-Type:" <<  ct <<endl;
                    }
                }
#endif
            }
        }

        curl_easy_cleanup(pCurl);

        pCurl = curl_easy_init();

        sleep (2);


        cout << "register device services" << endl;

        string  devSrvUrl = "http://60.205.212.99/squirrel/v1/devices/add_device_service_list";


        headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(pCurl, CURLOPT_URL, devSrvUrl.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, devSrvRegJsonObj.c_str()); 


        //some servers don't like requests that are made without a user-agent field, so we provide one  
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(pCurl);

        // check for errors
        if(res != CURLE_OK)
        {
            cout<<"ERROR: curl_easy_perform failed" << curl_easy_strerror(res) << endl;
        }
        else
        {
            //Now, our chunk.memory points to a memory block that is chunk.size
            //bytes big and contains the remote file.

            if(CURLE_OK == res)
            {
                long response_code;

                curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &response_code);

                if( response_code != 200)
                {
                    cout <<" Error! response code:"  << (int) response_code << endl;
                }

                else
                {
                    cout << "response code: 200" <<endl;
                }
#if 0
                char *ct;
                //ask for the content-type  
                res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                if((CURLE_OK == res) && ct)
                {
                    {
                        cout << "We received Content-Type:" <<  ct <<endl;
                    }
                }
#endif
            }
        }


        curl_easy_cleanup(pCurl);

        pCurl = curl_easy_init();


        cout << "register public services" << endl;

        string  pubSrvUrl = "http://60.205.212.99/squirrel/v1/public_service/add_public_service_list";


        headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(pCurl, CURLOPT_URL, pubSrvUrl.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, pubSrvRegJsonObj.c_str()); 


        //some servers don't like requests that are made without a user-agent field, so we provide one  
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(pCurl);

        // check for errors
        if(res != CURLE_OK)
        {
            cout<<"ERROR: curl_easy_perform failed" << curl_easy_strerror(res) << endl;
        }
        else
        {
            //Now, our chunk.memory points to a memory block that is chunk.size
            //bytes big and contains the remote file.

            if(CURLE_OK == res)
            {
                long response_code;

                curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &response_code);

                if( response_code != 200)
                {
                    cout <<" Error! response code:"  << (int) response_code << endl;
                }

                else
                {
                    cout << "response code: 200" <<endl;
                }
#if 0
                char *ct;
                //ask for the content-type  
                res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                if((CURLE_OK == res) && ct)
                {
                    {
                        cout << "We received Content-Type:" <<  ct <<endl;
                    }
                }
#endif
            }
        }

        curl_easy_cleanup(pCurl);

        pCurl = curl_easy_init();

        //create and write ini.conf
        ifstream robinConf("/var/www/robin.conf");
        if(!robinConf.is_open())
        {
            cout << "failed to open /var/www/robin.conf"<<endl;
            return -1;
        
        }

        ofstream iniConf("/var/www/ini.conf");

        if(!iniConf.is_open())   
        {
            cout << "failed to create /var/www/ini.conf"<<endl;
            return -1;
        }

        //write ini.conf
        iniConf << "BSSID=" << gApMac << endl;;
        
        iniConf << robinConf.rdbuf();

        robinConf.close();
        iniConf.close();


        //get device type

        string devicesUrl("http://60.205.212.99/ext/v1/router/devices?apMacAddress=");

        for(int i = 0; i < 18; i+=3)
        {   
            string tmpString = gApMac.substr(i,2);
            devicesUrl.append(tmpString);

            if( i < 15) 
            {
                devicesUrl.append("%3A");    
            }

        }   

        MemoryStruct getResponse;
        getResponse.memory = (char*) malloc(1);  // will be grown as needed by the realloc above 
        getResponse.size = 0;    // no data at this point 

        headers = NULL;
        headers = curl_slist_append(headers, "Accept: */*");

#ifdef DEBUG
        curl_slist_append(headers, "Authorization:");

#endif

        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(pCurl, CURLOPT_URL, devicesUrl.c_str());


        //register callback                                                                                                                                       
        curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, DeviceTypeCallback);
        curl_easy_setopt(pCurl, CURLOPT_WRITEDATA, (void *) &getResponse);

        //some servers don't like requests that are made without a user-agent field, so we provide one  
        curl_easy_setopt(pCurl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(pCurl);

        // check for errors
        if(res != CURLE_OK)
        {
            cout<<"ERROR: curl_easy_perform failed" << curl_easy_strerror(res) << endl;
        }
        else
        {
            //Now, our chunk.memory points to a memory block that is chunk.size
            //bytes big and contains the remote file.

            if(CURLE_OK == res)
            {
                long response_code;
                curl_easy_getinfo(pCurl, CURLINFO_RESPONSE_CODE, &response_code);

                if( response_code != 200)
                {
                    cout <<" Error! response code: " << (int) response_code << endl;
                    return false;
                }

                char *ct;
                //ask for the content-type  
                res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                if((CURLE_OK == res) && ct)
                {
                    cout << "We received Content-Type: " << ct << endl;;
                }
            }
            HandleQueryResponse (getResponse);
        }
     
        curl_easy_cleanup(pCurl);

        //create notification.shepherd
        
        ofstream notification("/var/www/notification.shepherd");

        milliseconds ms = duration_cast< milliseconds >( system_clock::now().time_since_epoch());
        notification << ms.count() << endl;
        




        return 0;

}

