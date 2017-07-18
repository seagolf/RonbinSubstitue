#include <cstring>                                                                                                                                                                                                 
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <vector>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#include <curl/curl.h>

#include "tinyxml2.h"

using namespace std;
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

bool getWanIpStub( string &wanIp)
{
    wanIp = "66.131.226.178";
    return true;

}


int main(int argc, char *argv[])
{
    vector <ScanInfoT> scanInfo;

    bool bUserRegisterStatus = false;
    string gApMac;
    string wanIp; 

    getWanIpStub(wanIp);
        

    if ( argc < 2 )
    {
        //cout << " please  input GW ip: " << endl;
        cout << "Usage: register <ip addr> [xml file1] [xml file2] ...[xml fileN] " << endl;
        return -1;
    }

    string apIpAddr(argv[1]);
    string apMacAddr;
    bool bInScan = false;
    bool bExScan = false;

    //parse xml

    for (int argvOffset=2; argvOffset < argc; argvOffset++)
    {
        if (strstr(argv[argvOffset], "in" ) != NULL)
        {
            bInScan = true;
            bExScan = false;
        }
        else if ( strstr (argv[argvOffset], "ex") !=NULL)
        {
            cout << "######ex xml scan " << endl;
            bExScan = true;
            bInScan = false;
            
        }

        else
        {
            cout << "wrong xml file input" << endl;
            cout << "there should be 'in' for inner scan xml, and 'ex' for external scan xml" << endl;
            continue;
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
        while (true) {
            pos = xml_str.find_first_of("<", pos);
            if (xml_str[pos + 1] == '?' || // <?xml...
                    xml_str[pos + 1] == '!') { // <!DOCTYPE... or [<!ENTITY...
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

        int tempIndex = 0;
        string jsonObj ("[");
        for ( vector<ScanInfoT>::iterator it = scanInfo.begin(); it !=scanInfo.end(); it++)
        {



            cout << "index : " << tempIndex << endl;
            ScanInfoT tmpInfo = *it;

            for ( vector <PortInfoT>::iterator itPort = tmpInfo.portInfo.begin(); itPort != tmpInfo.portInfo.end(); itPort++)
            {


                PortInfoT tmpPortInfo = *itPort;
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
                tempIndex ++;

                jsonObj.append("{\"apMacAddr\": \"");

                jsonObj.append (gApMac);
                jsonObj.append ("\","); 

                if( bInScan)
                {
                    jsonObj.append ("\"deviceMacAddr\": \"");
                    jsonObj.append (tmpInfo.devMacAddr);
                    jsonObj.append ("\",");
                }
                else if (bExScan)
                {
                    jsonObj.append ("\"userId:\":\"\""); 
                }

                jsonObj.append ("\"ip\": \"");
                jsonObj.append (tmpInfo.ipAddr);
                jsonObj.append ("\",");

                jsonObj.append ("\"port\": ");
                jsonObj.append (tmpPortInfo.portId);
                jsonObj.append (",");

                jsonObj.append ("\"protocol\": \"");
                jsonObj.append (tmpPortInfo.protocol);
                jsonObj.append ("\",");
#if 0
                jsonObj.append ("\"scanTimestamp\": \"");
                jsonObj.append (tmpInfo.scanTs);
                jsonObj.append ("\",");
#endif
                jsonObj.append ("\"service\": \"");
                jsonObj.append (tmpPortInfo.serviceName);
                jsonObj.append ("\",");

                jsonObj.append ("\"status\": \"");
                jsonObj.append (tmpPortInfo.status);
                jsonObj.append ("\"},");
            }
            jsonObj.append ("]");
        }

        //register
        CURL *pCurl;
        CURLcode res;

        pCurl = curl_easy_init();

        if (NULL == pCurl)
        {   
            cout << "faile to init curl" << endl;
            return false;
        }

        
        string url;
        struct curl_slist *headers = NULL;
        if (bUserRegisterStatus)
        {
            //regiseter AP and MacAddr
            url = "http://60.205.212.99/squirrel/v1/users";

            cout << url << endl;

            string regJsonObj;
            regJsonObj = "{\"userId\":\"hzspecTest\",\"password\":\"123456\",\"phoneNumber\":\"13912345678\",\"emailAddr\":\"nobody@hzspec.com\",\"apMacAddr\":\"";
            //if(gApMac.c_str() != NULL) 
            {
                regJsonObj.append(gApMac);
                regJsonObj.append("\",");
                regJsonObj.append("\"ip\":\"");
                regJsonObj.append(wanIp);
                regJsonObj.append("\"");
            }

            headers = curl_slist_append(headers, "Accept: application/json");
            headers = curl_slist_append(headers, "Content-Type: application/json");
            headers = curl_slist_append(headers, "charsets: utf-8");

            curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(pCurl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
            curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, regJsonObj.c_str()); 


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

                    char *ct;
                    //ask for the content-type  
                    res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                    if((CURLE_OK == res) && ct)
                    {
                        {
                            cout << "We received Content-Type:" <<  ct <<endl;
                        }
                    }
                }
            }
            bUserRegisterStatus = true;
        }





        if (bInScan)
        {
            url = "http://60.205.212.99/squirrel/v1/devices/add_device_service_list";

        }

        else if (bExScan)
        {
            url = "http://60.205.212.99/squirrel/v1/devices/add_public_service_list";
        
        }

        else
        {
            continue;
        }

        {
            cout << "URL: " << url << endl;
        }

        headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "charsets: utf-8");

        curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(pCurl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(pCurl, CURLOPT_POST, 1L);
        curl_easy_setopt(pCurl, CURLOPT_POSTFIELDS, jsonObj.c_str()); 


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

                char *ct;
                //ask for the content-type  
                res = curl_easy_getinfo(pCurl, CURLINFO_CONTENT_TYPE, &ct);

                if((CURLE_OK == res) && ct)
                {
                    {
                        cout << "We received Content-Type:" <<  ct <<endl;
                    }
                }
            }
        }

        curl_easy_cleanup(pCurl);

    }
}
