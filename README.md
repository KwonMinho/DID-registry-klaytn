## Klaytn DID 
 
'did:kt' (MUST: this string be in lowercase, this DID method is 'kaly')

klay-did = `did:kt: + klay-spceific-idstring `

klay-specific-idstring = 40*40HEXDIG
 
 
## CRUD Operation
 
클레이튼 DID들은 클레이튼 블록체인에서 저장되며, DID management smart contract인 'DidLedger'에서 관리된다.

### Create (해당 작업을 Register라고 부름)

레지스트리(스마트컨트랙트)의 `create` 메소드를 호출하여 생성할 수 있다.

하나의 클레이튼 계정은 오직 한번만 해당 함수를 실행할 수 있다.

### Read (Resolve)

DID 인증에 사용되는 DID 문서는 레지스트리(스마트컨트랙트)의 `getDocument` 메소드를 호출하여 조회할 수 있다.


### Update (Replace)

클레이튼 DID 문서를 업데이트하기 위하여, 관련 기능을 호출하기만 하면 된다.

`setController` 메서드를 호출하여, DID 인증에서 인증에서 사용할 `controller`(=delegate)를 추가할 수 있다.

`add_xxx` 메서드를 호출하여, DID 문서의 `public key`, `service` 항목을 추가할 수 있다.

전체 목록을 업데이트하는 방법은 제공하지 않는다.

### Delete (Revoke)

DID 문서의 항목을 삭제(비활성화)하기 위하여,아래 타입의 메서드를 호출하면 된다. 

타입은 `disable_xxx`

**DID document의 삭제는 해당 id를 다시 등록하거나 다시 활성화할 수 없음을 의미한다.**


## 보안 및 개인 정보 고려 사항

위와 같은 스펙을 구현할 때 고려해야할 보안 및 개인 정보 보호 고려 사항이 몇 가지 있다.

1. 현재 클레이튼 구현에서, 클레이튼 주소가 여러 DID를 갖는 것을 허용하지 않는다.
2. `controller` 속성에 지정된 대리자는 `public key` 값을 변경할 수 있으므로 DID 주체와 동일한 권한을 가집니다.
3. DID 문서에는 개인 정보를 저장해서는 안되며, 인증 방법 및 서비스 엔드포인트로 제한되어야한다.


## Implementation

### Bobbab testnet

DidLedger: 0xbCd509F468Fbc017fE615dE0b9cEfAa1Fbf335A6


## References
[references]: #references

[1]. Klaytn, https://www.klaytn.com/

[2]. W3C Decentralized Identifiers (DIDs) v1.0, https://w3c.github.io/did-core/
