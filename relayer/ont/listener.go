/*
 * Copyright (C) 2021 The poly network Authors
 * This file is part of The poly network library.
 *
 * The  poly network  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The  poly network  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with The poly network .  If not, see <http://www.gnu.org/licenses/>.
 */

package ont

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ontocommon "github.com/ontio/ontology/common"
	"github.com/ontio/ontology/merkle"
	ccom "github.com/ontio/ontology/smartcontract/service/native/cross_chain/common"
	outils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/polynetwork/bridge-common/base"
	"github.com/polynetwork/bridge-common/chains"
	"github.com/polynetwork/bridge-common/chains/ont"
	"github.com/polynetwork/bridge-common/chains/poly"
	"github.com/polynetwork/poly-relayer/config"
	"github.com/polynetwork/poly-relayer/eccm_abi"
	"github.com/polynetwork/poly-relayer/msg"
	polycommon "github.com/polynetwork/poly/common"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	pcom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	ontSDK1Client "github.com/rain-zxn/ontology-go-sdk/client"
	"strings"
	"time"
)

type Listener struct {
	sdk    *ont.SDK
	poly   *poly.SDK
	ccm    string
	ccd    string
	config *config.ListenerConfig
	name   string
}

func (l *Listener) Init(config *config.ListenerConfig, poly *poly.SDK) (err error) {
	if config.ChainId != uint64(5555) {
		return fmt.Errorf("ONT chain id is incorrect in config %v", config.ChainId)
	}
	l.config = config
	l.name = base.GetChainName(config.ChainId)
	l.ccm = outils.CrossChainContractAddress.ToHexString()
	l.poly = poly
	l.sdk, err = ont.WithOptions(config.ChainId, config.Nodes, time.Minute, 1)
	return
}

func (l *Listener) getProofHeight(txHeight uint64) (height uint64, err error) {
	h, err := l.poly.Node().GetSideChainHeight(l.config.ChainId)
	if err != nil {
		return 0, fmt.Errorf("getProofHeight unsupported chain %s err %v", l.name, err)
	}
	if txHeight >= h {
		height = txHeight
	} else {
		height = h
	}
	return
}

type MakeTxParamWithSender struct {
	Sender ontocommon.Address
	ccom.MakeTxParam
}

func (this *MakeTxParamWithSender) Serialization() (data []byte, err error) {
	sink := ontocommon.NewZeroCopySink(nil)
	sink.WriteAddress(ontocommon.Address(this.Sender))
	this.MakeTxParam.Serialization(sink)
	data = sink.Bytes()
	return
}

func (l *Listener) Compose(tx *msg.Tx) (err error) {
	if tx.SrcHeight == 0 {
		return fmt.Errorf("Invalid tx src height(0)")
	}
	v, err := l.poly.Node().GetSideChainMsg(uint64(5555), tx.SrcHeight)
	if err != nil {
		fmt.Println("err GetSideChainMsg", err)
		return fmt.Errorf("GetSideChainMsg:%s", err)
	}
	if len(v) == 0 {
		msg, err := l.sdk.Node().GetCrossChainMsg(uint32(tx.SrcHeight))
		if err != nil {
			fmt.Println("err ontNode.GetCrossChainMsg", err)
			return err
		}
		tx.SrcStateRoot, err = hex.DecodeString(msg)
		if err != nil {
			fmt.Println("err hex.DecodeString(msg)", err)
			return err
		}
	}
	var clientMgr ontSDK1Client.ClientMgr
	clientMgr.NewRpcClient().SetAddress("http://43.128.242.133:20336")
	hashes, err := clientMgr.GetCrossStatesLeafHashes(float64(tx.SrcHeight))
	if err != nil {
		fmt.Println("err GetCrossStatesLeafHashes", err)
		return fmt.Errorf("GetCrossStatesLeafHashes:%s", err)
	}
	eccmAddr := "30d4e2cf64d5d8f9da4dd7f094c6c01f3aa2d434"
	param := ccom.MakeTxParam{}
	par, _ := hex.DecodeString(tx.SrcParam)
	err = param.Deserialization(ontocommon.NewZeroCopySource(par))
	if err != nil {
		fmt.Println("err param.Deserialization:", err)
		return err
	}
	fmt.Println("ontocommon.ToHexString(param.TxHash):", ontocommon.ToHexString(param.TxHash))
	ontEccmAddr, err := ontocommon.AddressFromHexString(eccmAddr)
	fmt.Println("ontEccmAddr", ontEccmAddr, ontEccmAddr.ToHexString())

	makeTxParamWithSender := &MakeTxParamWithSender{
		ontEccmAddr,
		param,
	}
	itemValue, err := makeTxParamWithSender.Serialization()
	if err != nil {
		fmt.Println("err makeTxParamWithSender.Serialization:", err)
		return err
	}
	hashesx := make([]ontocommon.Uint256, 0)
	for _, v := range hashes.Hashes {
		uint256v, _ := ontocommon.Uint256FromHexString(v)
		hashesx = append(hashesx, uint256v)
	}
	path, err := merkle.MerkleLeafPath(itemValue, hashesx)
	if err != nil {
		fmt.Println("err  merkle.MerkleLeafPath:", err)
		return err
	}
	fmt.Println("string(path):", ontocommon.ToHexString(path))
	tx.SrcProof = path
	tx.Param = &pcom.MakeTxParam{
		TxHash:              param.TxHash,
		CrossChainID:        param.CrossChainID,
		FromContractAddress: param.FromContractAddress,
		ToChainID:           param.ToChainID,
		ToContractAddress:   param.ToContractAddress,
		Method:              param.Method,
		Args:                param.Args,
	}
	//{
	//	value, _, _, _ := msg.ParseAuditPath(tx.SrcProof)
	//	if len(value) == 0 {
	//		return fmt.Errorf("ParseAuditPath got null param")
	//	}
	//	param := &ccom.MakeTxParam{}
	//	err = param.Deserialization(ontocommon.NewZeroCopySource(value))
	//	if err != nil {
	//		return
	//	}
	//	tx.Param = &pcom.MakeTxParam{
	//		TxHash:              param.TxHash,
	//		CrossChainID:        param.CrossChainID,
	//		FromContractAddress: param.FromContractAddress,
	//		ToChainID:           param.ToChainID,
	//		ToContractAddress:   param.ToContractAddress,
	//		Method:              param.Method,
	//		Args:                param.Args,
	//	}
	//}
	return
}

func (l *Listener) Header(height uint64) (header []byte, hash []byte, err error) {
	block, err := l.sdk.Node().GetBlockByHeight(uint32(height))
	if err != nil {
		return
	}
	info := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(block.Header.ConsensusPayload, info); err != nil {
		return nil, nil, fmt.Errorf("ONT unmarshal blockInfo error: %s", err)
	}
	if info.NewChainConfig != nil {
		return block.Header.ToArray(), nil, nil
	}
	return
}

type StorageLog struct {
	Address common.Address
	Topics  []common.Hash
	Data    []byte
}

func (self *StorageLog) Serialization(sink *polycommon.ZeroCopySink) {
	sink.WriteAddress(polycommon.Address(self.Address))
	sink.WriteUint32(uint32(len(self.Topics)))
	for _, t := range self.Topics {
		sink.WriteHash(polycommon.Uint256(t))
	}
	sink.WriteVarBytes(self.Data)
}

func (self *StorageLog) Deserialization(source *polycommon.ZeroCopySource) error {
	address, _ := source.NextAddress()
	self.Address = common.Address(address)
	l, _ := source.NextUint32()
	self.Topics = make([]common.Hash, 0, l)
	for i := uint32(0); i < l; i++ {
		h, _ := source.NextHash()
		self.Topics = append(self.Topics, common.Hash(h))
	}
	data, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("StorageLog.Data eof")
	}
	self.Data = data
	return nil
}

func (l *Listener) Scan(height uint64) (txs []*msg.Tx, err error) {
	events, err := l.sdk.Node().GetSmartContractEventByBlock(uint32(height))
	if err != nil {
		fmt.Println("GetSmartContractEventByBlock err:", err)
		return nil, fmt.Errorf("ONT failed to fetch smart contract events for height %d, err %v", height, err)
	}
	flag := 0
	txs = []*msg.Tx{}
	l.ccm = "30d4e2cf64d5d8f9da4dd7f094c6c01f3aa2d434"
	for _, event0 := range events {
		fmt.Println("event hash:", event0.TxHash)
		for _, notify := range event0.Notify {
			fmt.Println("Scan notify.ContractAddress:", notify.ContractAddress)
			fmt.Println("Scan l.ccm:", l.ccm)
			if notify.ContractAddress == l.ccm {
				flag++
				states, ok := notify.States.(string)
				if !ok {
					fmt.Println("event info states is not string")
					continue
				}
				var data []byte
				data, err = hexutil.Decode(states)
				if err != nil {
					err = fmt.Errorf("decoding states err:%v", err)
					return nil, err
				}
				source := polycommon.NewZeroCopySource(data)
				var storageLog StorageLog
				err = storageLog.Deserialization(source)
				if err != nil {
					return nil, err
				}
				var parsed abi.ABI
				parsed, err = abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
				if err != nil {
					return nil, err
				}
				var event eccm_abi.EthCrossChainManagerCrossChainEvent
				err = parsed.UnpackIntoInterface(&event, "CrossChainEvent", storageLog.Data)
				if err != nil {
					return nil, err
				}
				fmt.Println("CrossChainEvent", event)

				tx := &msg.Tx{
					TxId:       msg.EncodeTxId(event.TxId),
					TxType:     msg.SRC,
					SrcHeight:  height,
					SrcChainId: 5555,
					SrcHash:    event0.TxHash,
					DstChainId: event.ToChainId,
					SrcParam:   hex.EncodeToString(event.Rawdata),
					//SrcProofHeight: height,
					//SrcEvent:       event.Rawdata,
				}
				txs = append(txs, tx)
				jsontx, _ := json.Marshal(tx)
				fmt.Println(string(jsontx))
			}
		}
	}
	return
}

func (l *Listener) GetTxBlock(hash string) (height uint64, err error) {
	h, err := l.sdk.Node().GetBlockHeightByTxHash(hash)
	height = uint64(h)
	return
}

func (l *Listener) ScanTx(hash string) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) scanTx(hash string, height uint64) (tx *msg.Tx, err error) {
	return
}

func (l *Listener) ListenCheck() time.Duration {
	duration := time.Second
	if l.config.ListenCheck > 0 {
		duration = time.Duration(l.config.ListenCheck) * time.Second
	}
	return duration
}

func (l *Listener) Nodes() chains.Nodes {
	return l.sdk.ChainSDK
}

func (l *Listener) ChainId() uint64 {
	return l.config.ChainId
}

func (l *Listener) Defer() int {
	return l.config.Defer
}

func (l *Listener) LastHeaderSync(force, last uint64) (height uint64, err error) {
	if l.poly == nil {
		err = fmt.Errorf("No poly sdk provided for NEO FetchLastConsensus")
		return
	}
	if force != 0 {
		return force, nil
	}
	height, err = l.poly.Node().GetSideChainMsgHeight(uint64(5555))
	if err != nil {
		return
	}
	if height == 0 {
		height, err = l.poly.Node().GetSideChainHeight(uint64(5555))
	}
	if last > height {
		height = last
	}
	return
}
