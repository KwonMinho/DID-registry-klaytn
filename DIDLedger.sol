pragma solidity 0.5.6;
pragma experimental ABIEncoderV2;

import './Storage.sol';
import './DidUtils.sol';

/**
 * @title DidLedger
 * @dev This contract is did document storage implementation
 */
contract DidLedger is Storage{
    
    modifier verifyFormat(string memory did){
        require(DidUtils.verifyDidFormat(did),'Invalid format');
        _;
    }
    
    modifier onlyOwners(string memory did, address actor){
        string memory actorDid = DidUtils.genDid(actor);
        string memory controller = documents[did].controller;
        require(DidUtils.verifyOwners(did,actorDid,controller),'Not permission');
        _;
    }
    
    modifier checkActiveDom(string memory did){
        require(didState[did] == DIDState.Active,"None or Deactivated");
        _;
    }
    
    modifier checkExistDom(){
        string memory did = DidUtils.genDid(msg.sender);
        require(didState[did] == DIDState.None,"Already Document");
        _;
    }
    
    function create() public checkExistDom
    {
        string memory did = DidUtils.genDid(msg.sender);
        string memory keyID = DidUtils.genPublicKeyID(did,1);
        string memory addrKey = DidUtils.genAddrKey(msg.sender);
        string memory keyType = 'EcdsaSecp256k1RecoveryMethod2020';
        PublicKey memory defaultKey = PublicKey(keyID,keyType,did,addrKey,false);
        documents[did].contexts.push("https://www.w3.org/ns/did/v1");
        documents[did].id = did;
        documents[did].publicKeys.push(defaultKey);
        didState[did] = DIDState.Active;
    }
    
    
    function setController(
        string memory did, 
        string memory delegate) public
    {
        setController(did,delegate,msg.sender);
    }
    
    
    function setControllerBySign(
        string memory did, 
        string memory delegate, 
        uint8 v, bytes32 r, bytes32 s) public
    {
        setController(did,delegate,recoverSignature(did,'setController',v,r,s));
    }
    
    
    function setController(
        string memory did, 
        string memory delegate, 
        address actor) internal
        verifyFormat(did) verifyFormat(delegate) onlyOwners(did, actor)
    {
        documents[did].controller = delegate;
    }
    
    
    function addPubKey(
        string memory did,
        string memory pubKey,
        string memory controller) public 
    {
        addPubKey(did,pubKey,controller,msg.sender);        
    }
    
    
    function addPubKeyBySign(
        string memory did,
        string memory pubKey,
        string memory controller,
        uint8 v,bytes32 r,bytes32 s) public 
    {
        addPubKey(did,pubKey,controller,recoverSignature(did,'addPubKey',v,r,s));        
    }
    
    
    function addPubKey(
        string memory did,
        string memory pubKey,
        string memory controller,
        address actor) internal 
        verifyFormat(did) verifyFormat(controller) 
        checkActiveDom(did) onlyOwners(did, actor)
    {
        uint256 index = documents[did].publicKeys.length;
        string memory keyID = DidUtils.genPublicKeyID(did,index+1);
        string memory keyType = 'EcdsaSecp256k1VerificationKey2019';
        documents[did].publicKeys.push(PublicKey(keyID,keyType,controller,pubKey,false));
    }
    
    
    function addAddrKey(
        string memory did,
        address addr,
        string memory controller) public
    {
        addAddrKey(did,addr,controller,msg.sender);    
    }
    
    
    function addAddrKeyBySign(
        string memory did,
        address addr,
        string memory controller,
        uint8 v,bytes32 r,bytes32 s) public
    {
        addAddrKey(did,addr,controller,recoverSignature(did,'addAddrKey',v,r,s));        
    }
    
    
    function addAddrKey(
        string memory did,
        address addr,
        string memory controller,
        address actor) internal 
        verifyFormat(did) checkActiveDom(did) onlyOwners(did, actor)
    {
        uint256 index = documents[did].publicKeys.length;
        string memory keyID = DidUtils.genPublicKeyID(did,index+1);
        string memory keyType = 'EcdsaSecp256k1RecoveryMethod2020';
        string memory keyAddr = DidUtils.genAddrKey(addr);
        documents[did].publicKeys.push(PublicKey(keyID,keyType,controller,keyAddr,false));  
    }
    
    function addService(
        string memory did,
        string memory scvID,
        string memory scvType,
        string memory scvEndpoint) public 
    {
        addService(did, scvID, scvType, scvEndpoint, msg.sender);    
    }
    
    function addServiceBySign(
        string memory did,
        string memory scvID,
        string memory scvType,
        string memory scvEndpoint,
        uint8 v,bytes32 r,bytes32 s) public 
    {
        addService(did, scvID, scvType, scvEndpoint, recoverSignature(did,'addService',v,r,s));    
    }
    
    function addService(
        string memory did,
        string memory scvID,
        string memory scvType,
        string memory scvEndpoint,
        address actor)internal 
        verifyFormat(did) checkActiveDom(did) onlyOwners(did,actor)
    {
        string memory id =  DidUtils.genFragment(did,scvID);
        documents[did].services.push(Service(id,scvType,scvEndpoint,false));
    }

    function disableKey(
        string memory did,
        string memory targetId) public
    {
       disableKey(did, targetId, msg.sender);     
    }
    
    function disableKey(
        string memory did,
        string memory targetId,
        uint8 v,bytes32 r,bytes32 s) public 
    {
        disableKey(did, targetId,recoverSignature(did,'disableKey',v,r,s));    
    }
    
    function disableKey(
        string memory did,
        string memory targetId,
        address actor) 
        internal verifyFormat(did) checkActiveDom(did) onlyOwners(did, actor)    
    {
        for(uint256 i=0; i<documents[did].publicKeys.length; i++){
            string memory id = documents[did].publicKeys[i].id;
            if(DidUtils.equalString(id,targetId)){
                documents[did].publicKeys[i].disable = true;
            }
        }
    }
    
    function disableService(
        string memory did,
        string memory targetId
        ) public
    {
        disableService(did, targetId, msg.sender);        
    }
    
    function disableService(
        string memory did,
        string memory targetId,
        uint8 v,bytes32 r,bytes32 s
        ) public
    {
        disableService(did,targetId,recoverSignature(did,'disableService',v,r,s));
    }
    
    function disableService(
        string memory did,
        string memory targetId, 
        address actor) internal
        verifyFormat(did) checkActiveDom(did) onlyOwners(did,actor)   
    {
        for(uint256 i=0; i<documents[did].services.length; i++){
            string memory id = documents[did].services[i].id;
            if(DidUtils.equalString(id,targetId)){
                documents[did].services[i].disable = true;
            }
        }
    }
    
    function deactivatedDom(string memory did) 
        public
        verifyFormat(did)
        checkActiveDom(did)
        onlyOwners(did, msg.sender)   
    {
        didState[did] = DIDState.Deactivated;
    } 

    
    function getDocument(string memory did) public view 
        verifyFormat(did) 
        returns(Document memory) 
    {
        Document memory dom = documents[did];
        for(uint256 i=0;i<dom.services.length;i++){
            if(dom.services[i].disable) delete dom.services[i];
        }
        for(uint256 i=0;i<dom.publicKeys.length;i++){
            if(dom.publicKeys[i].disable) delete dom.publicKeys[i];
        }
        return  dom;
    }
    
    function recoverSignature(
        string memory did, 
        string memory fType, 
        uint8 sigV, bytes32 sigR, bytes32 sigS) internal 
        returns(address)
    {
        bytes32 hash =  DidUtils.genSignHash(fType, address(this), nonce[did], did);
        address signer = ecrecover(hash, sigV, sigR, sigS);
        nonce[did]++;
        return signer;
    }
}