pragma solidity 0.5.6;
pragma experimental ABIEncoderV2;

library DidUtils{
    
    // "did:kt:f269E60fF7280e3E11b7EEd7B76b5C005105D121"
    function verifyDidFormat(string memory did) public pure 
        returns(bool)
    {
        bytes memory data = bytes(did);
        if(data.length != 47) return false;
        bytes memory prefix = bytes("did:kt:");
        bytes memory dataPrefix = _slice(data,0,prefix.length);
        bytes memory addressBytes = _fromHex(string(_slice(data,prefix.length,40)));
        if(!_equal(prefix, dataPrefix)) return false;
        return (addressBytes.length == 20);
    }
    
    
    function verifyOwners(
        string memory did, 
        string memory actor, 
        string memory controller) public pure returns(bool)
    {
        if(_equal(bytes(did), bytes(actor))) return true;
        if(_equal(bytes(controller), bytes(actor))) return true;
        return false;
    }
    
    
    function genDid(address addr) public pure returns(string memory)
    {
        return string(abi.encodePacked('did:kt:',_addrToString(addr)));
    }
    
    
    function genPublicKeyID(
        string memory did, 
        uint256 index) public pure returns(string memory)
    {
        return string(abi.encodePacked(did,'#key-', _uintToStr(index)));
    }
    
    
    function genAddrKey(
        address addr) public pure returns(string memory)
    {
        return string(abi.encodePacked('0x',_addrToString(addr)));
    }
    
    
    function genFragment(
        string memory did, 
        string memory id) public pure returns(string memory)
    {
        return string(abi.encodePacked(did,'#',id));
    }
    
    function genSignHash(
        string memory fType,
        address ledger,
        uint256 nonce,
        string memory did) public view returns(bytes32 signHash)
    {
        bytes memory prefix = "\x19Klaytn Signed Message:\n";
        string memory registry = string(abi.encodePacked('0x',_addrToString(ledger)));
        bytes memory message = abi.encodePacked(fType,registry,_uintToStr(nonce),did);
        return keccak256(abi.encodePacked(prefix,_uintToStr(message.length),message));
    }    


    function equalString(
        string memory str1, 
        string memory str2) public pure returns(bool)
    {
        return _equal(bytes(str1),bytes(str2));
    }
    
    function uintToStr(uint i) public pure returns(string memory){
        return _uintToStr(i);
    }
    
    
    function _bytesToAddr(bytes memory _bs)
        internal
        pure
        returns (address addr)
    {
        require(_bs.length == 20, "bytes length does not match address");
        assembly {
            addr := mload(add(_bs, 0x14))
        }
    }    
    
    
    function _uintToStr(uint256 _i) internal pure returns(string memory _uintAsString)
    {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len - 1;
        while (_i != 0) {
            bstr[k--] = bytes1(uint8(48 + (_i % 10)));
            _i /= 10;
        }
        return string(bstr);
    }
    
    
    function _addrToString(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            byte b = byte(uint8(uint(x) / (2**(8*(19 - i)))));
            byte hi = byte(uint8(b) / 16);
            byte lo = byte(uint8(b) - 16 * uint8(hi));
            s[2*i] = _char(hi);
            s[2*i+1] = _char(lo);            
        }
        return string(s);
    }


    function _char(byte b) internal pure returns (byte c) {
        if (uint8(b) < 10) return byte(uint8(b) + 0x30);
        else return byte(uint8(b) + 0x57);
    }


    function _equal(bytes memory _preBytes, bytes memory _postBytes)
        internal pure returns (bool)
    {
        bool success = true;
        assembly {
            let length := mload(_preBytes)
            switch eq(length, mload(_postBytes))
                case 1 {
                    let cb := 1
                    let mc := add(_preBytes, 0x20)
                    let end := add(mc, length)

                    for {
                        let cc := add(_postBytes, 0x20)
                    } eq(add(lt(mc, end), cb), 2) {
                        mc := add(mc, 0x20)
                        cc := add(cc, 0x20)
                    } {
                        if iszero(eq(mload(mc), mload(cc))) {
                            success := 0
                            cb := 0
                        }
                    }
                }
                default {
                    success := 0
                }
        }
        return success;
    }
    
    
    function _slice(bytes memory _bytes,uint256 _start,uint256 _length) 
        internal pure returns (bytes memory) 
    {
        require(_bytes.length >= (_start + _length));
        bytes memory tempBytes;
        assembly {
            switch iszero(_length)
                case 0 {
                    tempBytes := mload(0x40)

                    let lengthmod := and(_length, 31)

                    let mc := add(
                        add(tempBytes, lengthmod),
                        mul(0x20, iszero(lengthmod))
                    )
                    let end := add(mc, _length)
                    
                    for {
                        let cc := add(
                            add(
                                add(_bytes, lengthmod),
                                mul(0x20, iszero(lengthmod))
                            ),
                            _start
                        )
                    } lt(mc, end) {
                        mc := add(mc, 0x20)
                        cc := add(cc, 0x20)
                    } {
                        mstore(mc, mload(cc))
                    }
                    mstore(tempBytes, _length)
                    mstore(0x40, and(add(mc, 31), not(31)))
                }
                default {
                    tempBytes := mload(0x40)

                    mstore(0x40, add(tempBytes, 0x20))
                }
        }
        return tempBytes;
    }
    
    
    function _fromHex(string memory s) internal pure returns (bytes memory) {
        bytes memory ss = bytes(s);
        require(ss.length % 2 == 0);
        bytes memory r = new bytes(ss.length / 2);
        for (uint256 i = 0; i < ss.length / 2; ++i) {
            r[i] = bytes1(
                _fromHexChar(uint8(ss[2 * i])) *
                    16 +
                    _fromHexChar(uint8(ss[2 * i + 1]))
            );
        }
        return r;
    }
    
    
    function _fromHexChar(uint8 c) internal pure returns (uint8) {
        if (bytes1(c) >= bytes1("0") && bytes1(c) <= bytes1("9")) {
            return c - uint8(bytes1("0"));
        }
        if (bytes1(c) >= bytes1("a") && bytes1(c) <= bytes1("f")) {
            return 10 + c - uint8(bytes1("a"));
        }
        if (bytes1(c) >= bytes1("A") && bytes1(c) <= bytes1("F")) {
            return 10 + c - uint8(bytes1("A"));
        }
        revert();
    }
}