pragma solidity 0.5.6;


/**
 * @title Storage
 * @dev This contract is storage that
 */
contract Storage{

    mapping(string => Document) documents;
    mapping(string => DIDState) didState;
    mapping(string => uint) public nonce;
    
    enum DIDState {None, Active, Deactivated}

    struct PublicKey{
        string id;
        string keyType;
        string controller;
        string pubKeyData;
        bool disable;
    }
    
    struct Service{
        string id;
        string serviceType;
        string serviceEndPoint;
        bool disable;
    }
    
    struct Document{
        string[] contexts;
        string id;
        string controller;
        PublicKey[] publicKeys;
        Service[] services;
    }
}