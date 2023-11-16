// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;
import "hardhat/console.sol";

contract TestVerify {

// input hash: 0x40911617a71a9442f5406f296f1534892a281b711587fb4a2eb4fef45cf5a181
// output hash: 0x50b0f7f997adaa03dfecfa2e3de0c707cdef3cff797eb0157d6d03fb2ff7e840
// proof: 0x1332c772a8f9a02f304b5472d3b6b75f1a494bd9b137fc663fd5b9b475992bc829ba08f7cfa745e340938e356b139224d0288b9511a5cec83235f969f61a94ed16a14579fa0adcc3bf8da36209f64547fd5ff4e1c7e8b5b151335b5b4a471de3115f83b696517ac68ae7620f7d3840e44aff4781c0a4d265a2905ef9bcaa04432a660197790e60d1135946ae0603ef69a5ecb45b6f8046167f902dc6d8a35cf716bce116484dfa4fcd5d8f4c2fda26d68754b56e68f1a877d95dc171accc34d71285068693fe3d8d28e66342c31292ceee5c6d87fcb8ad8c132363565f2aeff905726b2d35def5c9636dd5ec402d8d6f6c9a7be7977e7e5727da327ea5b079ad
function verify(bytes32 _inputHash, bytes32 _outputHash, bytes memory _proof) external view returns (bool) {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
        abi.decode(_proof, (uint256[2], uint256[2][2], uint256[2]));            
        
        console.logString("Point a:");
        console.logUint(a[0]);
        console.logUint(a[1]);

        console.logString("Point b:");
        console.logUint(b[0][0]);
        console.logUint(b[0][1]);
        console.logUint(b[1][0]);
        console.logUint(b[1][1]);
            
        console.logString("Point c:");
        console.logUint(c[0]);
        console.logUint(c[1]);

        uint256[2] memory input = [uint256(_outputHash), uint256(_inputHash)];
        input[0] = input[0] & ((1 << 253) - 1);
        input[1] = input[1] & ((1 << 253) - 1);

        console.logString("Public input: ");
        console.logUint(input[0]);
        console.logUint(input[1]);


        verifyProof(a, b, c, input);

    }


     // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 202333273032481017331373350816007583026713320195536354260471885571526195724;
    uint256 constant IC0y = 8246242704115088390751476790768744984402990892657920674334938931948100192840;
    
    uint256 constant IC1x = 12901454334783146822957332552289769626984444933652541503990843020723194328882;
    uint256 constant IC1y = 12436078488518552293095332739673622487901350475115357313978341690183990059269;
    
    uint256 constant IC2x = 12828056956769114977702246128118682473179646035440405756936949778100648490262;
    uint256 constant IC2y = 7351319165217643779735289066901404053730163225836026220896225559268517203790;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] memory _pA, uint[2][2] memory _pB, uint[2] memory _pC, uint[2] memory _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, mload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, mload(add(pubSignals, 32)))
                

                // -A
                mstore(_pPairing, mload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, mload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), mload(pB))
                mstore(add(_pPairing, 96), mload(add(pB, 32)))
                mstore(add(_pPairing, 128), mload(add(pB, 64)))
                mstore(add(_pPairing, 160), mload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), mload(pC))
                mstore(add(_pPairing, 608), mload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(mload(add(_pubSignals, 0)))
            
            checkField(mload(add(_pubSignals, 32)))
            
            checkField(mload(add(_pubSignals, 64)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, add(_pB, 64), _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
}
