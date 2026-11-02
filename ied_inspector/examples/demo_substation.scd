<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="DemoSubstation" version="1" revision="A" toolID="IED Inspector demo" nameStructure="IEDName"/>
  <Communication>
    <SubNetwork name="StationBus" type="8-MMS">
      <ConnectedAP iedName="PROT_Q01" apName="S1">
        <Address><P type="IP">10.10.1.11</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.1.1</P><P type="OSI-AP-Title">1,1,9999,1</P><P type="OSI-AE-Qualifier">12</P><P type="OSI-PSEL">00000001</P><P type="OSI-SSEL">0001</P><P type="OSI-TSEL">0001</P></Address>
        <GSE ldInst="PROT" cbName="GCB_TRIP"><Address><P type="MAC-Address">01-0C-CD-01-00-11</P><P type="APPID">0011</P><P type="VLAN-ID">00A</P><P type="VLAN-PRIORITY">4</P></Address><MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime></GSE>
        <GSE ldInst="PROT" cbName="GCB_POS"><Address><P type="MAC-Address">01-0C-CD-01-00-12</P><P type="APPID">0012</P><P type="VLAN-ID">014</P><P type="VLAN-PRIORITY">4</P></Address><MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime></GSE>
      </ConnectedAP>
      <ConnectedAP iedName="CTRL_Q01" apName="S1">
        <Address><P type="IP">10.10.1.21</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.1.1</P><P type="OSI-AP-Title">1,1,9999,1</P><P type="OSI-AE-Qualifier">12</P><P type="OSI-PSEL">00000001</P><P type="OSI-SSEL">0001</P><P type="OSI-TSEL">0001</P></Address>
        <GSE ldInst="CTRL" cbName="GCB_ILOCK"><Address><P type="MAC-Address">01-0C-CD-01-00-21</P><P type="APPID">0021</P><P type="VLAN-ID">00A</P><P type="VLAN-PRIORITY">4</P></Address><MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime></GSE>
      </ConnectedAP>
      <ConnectedAP iedName="PROT_Q02" apName="S1">
        <Address><P type="IP">10.10.1.12</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.1.1</P><P type="OSI-AP-Title">1,1,9999,1</P><P type="OSI-AE-Qualifier">12</P><P type="OSI-PSEL">00000001</P><P type="OSI-SSEL">0001</P><P type="OSI-TSEL">0001</P></Address>
        <GSE ldInst="PROT" cbName="GCB_TRIP"><Address><P type="MAC-Address">01-0C-CD-01-00-31</P><P type="APPID">0011</P><P type="VLAN-ID">0A</P><P type="VLAN-PRIORITY">4</P></Address><MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime></GSE>
      </ConnectedAP>
      <ConnectedAP iedName="PMS_CI868" apName="S1">
        <Address><P type="IP">10.10.1.50</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.1.1</P><P type="OSI-AP-Title">1,1,9999,1</P><P type="OSI-AE-Qualifier">12</P><P type="OSI-PSEL">00000001</P><P type="OSI-SSEL">0001</P><P type="OSI-TSEL">0001</P></Address>
        <GSE ldInst="PMS" cbName="GCB_LS"><Address><P type="MAC-Address">01-0C-CD-01-00-51</P><P type="APPID">0051</P><P type="VLAN-ID">00A</P><P type="VLAN-PRIORITY">4</P></Address><MinTime unit="s" multiplier="m">4</MinTime><MaxTime unit="s" multiplier="m">1000</MaxTime></GSE>
      </ConnectedAP>
    </SubNetwork>
    <SubNetwork name="ProcessBus" type="8-MMS">
      <ConnectedAP iedName="MU_Q01" apName="S1">
        <Address><P type="IP">10.10.2.31</P><P type="IP-SUBNET">255.255.255.0</P><P type="IP-GATEWAY">10.10.1.1</P><P type="OSI-AP-Title">1,1,9999,1</P><P type="OSI-AE-Qualifier">12</P><P type="OSI-PSEL">00000001</P><P type="OSI-SSEL">0001</P><P type="OSI-TSEL">0001</P></Address>
        <SMV ldInst="MU" cbName="MSVCB01"><Address><P type="MAC-Address">01-0C-CD-04-00-01</P><P type="APPID">4000</P><P type="VLAN-ID">028</P><P type="VLAN-PRIORITY">4</P></Address></SMV>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  
  <IED name="PROT_Q01" type="DemoRelay" manufacturer="DemoVendor" configVersion="1.0" desc="Feeder Q01 protection">
    <Services><GOOSE max="8"/><GSESettings/><SMVSettings/><GetDirectory/><GetDataObjectDefinition/><DataObjectDirectory/><GetDataSetValue/><DataSetDirectory/><ReadWrite/><ConfDataSet max="10"/></Services>
    <AccessPoint name="S1">
      <Server><Authentication/>
        <LDevice inst="PROT">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DOI name="Mod"><DAI name="stVal"><Val>on</Val></DAI><DAI name="ctlModel"><Val>status-only</Val></DAI></DOI>
            <DOI name="NamPlt"><DAI name="vendor"><Val>Demo</Val></DAI><DAI name="swRev"><Val>1.0</Val></DAI><DAI name="configRev"><Val>R1</Val></DAI></DOI>
            <DataSet name="DS_TRIP"><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Str" daName="general" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Str" daName="q" fc="ST"/></DataSet>
            <DataSet name="DS_POS"><FCDA ldInst="PROT" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="GGIO" lnInst="1" doName="AnIn1" fc="MX"/></DataSet>
            <ReportControl name="URCB_PMS" datSet="DS_POS" rptID="PROT_Q01_PMS" confRev="1" buffered="false" intgPd="0"><TrgOps dchg="true" qchg="true"/><OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true"/><RptEnabled max="1"><ClientLN iedName="PMS_CI868" ldInst="PMS" lnClass="IHMI" lnInst="1"/></RptEnabled></ReportControl>
            <GSEControl name="GCB_TRIP" type="GOOSE" appID="PROT_Q01_TRIP" datSet="DS_TRIP" confRev="1"/>
            <GSEControl name="GCB_POS" type="GOOSE" appID="PROT_Q01_POS" datSet="DS_POS" confRev="3"/>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_T"><DOI name="PhyNam"><DAI name="vendor"><Val>Demo Vendor</Val></DAI><DAI name="model"><Val>Demo Model</Val></DAI></DOI></LN>
          <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
          <LN lnClass="XCBR" inst="1" prefix="" lnType="XCBR_T"><DOI name="Pos"><DAI name="stVal"><Val>on</Val></DAI></DOI></LN>
          <LN lnClass="GGIO" inst="1" prefix="" lnType="GGIO_T"><DOI name="AnIn1"><SDI name="mag"><DAI name="f"><Val>12.5</Val></DAI></SDI></DOI></LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  
  <IED name="CTRL_Q01" type="DemoBCU" manufacturer="DemoVendor" configVersion="1.0" desc="Bay Q01 controller">
    <Services><GOOSE max="8"/><GSESettings/><SMVSettings/><GetDirectory/><GetDataObjectDefinition/><DataObjectDirectory/><GetDataSetValue/><DataSetDirectory/><ReadWrite/><ConfDataSet max="10"/></Services>
    <AccessPoint name="S1">
      <Server><Authentication/>
        <LDevice inst="CTRL">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DOI name="Mod"><DAI name="stVal"><Val>on</Val></DAI><DAI name="ctlModel"><Val>status-only</Val></DAI></DOI>
            <DOI name="NamPlt"><DAI name="vendor"><Val>Demo</Val></DAI><DAI name="swRev"><Val>1.0</Val></DAI><DAI name="configRev"><Val>R1</Val></DAI></DOI>
            <DataSet name="DS_ILOCK"><FCDA ldInst="CTRL" prefix="" lnClass="CILO" lnInst="1" doName="EnaOpn" daName="stVal" fc="ST"/><FCDA ldInst="CTRL" prefix="" lnClass="CILO" lnInst="1" doName="EnaCls" daName="stVal" fc="ST"/></DataSet>
            <GSEControl name="GCB_ILOCK" type="GOOSE" appID="CTRL_Q01_ILOCK" datSet="DS_ILOCK" confRev="1"/>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_T"><DOI name="PhyNam"><DAI name="vendor"><Val>Demo Vendor</Val></DAI><DAI name="model"><Val>Demo Model</Val></DAI></DOI></LN>
          <LN lnClass="CILO" inst="1" prefix="" lnType="CILO_T"><DOI name="EnaOpn"><DAI name="stVal"><Val>true</Val></DAI></DOI></LN>
          <LN lnClass="LGOS" inst="1" prefix="" lnType="LGOS_T"><DOI name="GoCBRef"><DAI name="setSrcRef"><Val>PROT_Q01PROT/LLN0.GCB_TRIP</Val></DAI></DOI></LN>
          <LN lnClass="LGOS" inst="2" prefix="" lnType="LGOS_T"><DOI name="GoCBRef"><DAI name="setSrcRef"><Val>PROT_Q01PROT/LLN0.GCB_POS</Val></DAI></DOI></LN>
          <LN lnClass="LGOS" inst="3" prefix="" lnType="LGOS_T"><DOI name="GoCBRef"><DAI name="setSrcRef"><Val>PROT_Q02PROT/LLN0.GCB_TRIP</Val></DAI></DOI></LN>
          <LN lnClass="CSWI" inst="1" prefix="" lnType="CSWI_T">
            <Inputs>
              <ExtRef iedName="PROT_Q01" ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcCBName="GCB_TRIP" intAddr="TripIn"/>
              <ExtRef iedName="PROT_Q01" ldInst="PROT" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" serviceType="GOOSE" srcLDInst="PROT" srcCBName="GCB_POS" intAddr="PosIn"/>
              <ExtRef iedName="PROT_Q02" ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcCBName="GCB_TRIP" intAddr="Trip2In"/>
            </Inputs>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  
  <IED name="PROT_Q02" type="DemoRelay" manufacturer="DemoVendor" configVersion="1.0" desc="Feeder Q02 protection">
    <Services><GOOSE max="8"/><GSESettings/><SMVSettings/><GetDirectory/><GetDataObjectDefinition/><DataObjectDirectory/><GetDataSetValue/><DataSetDirectory/><ReadWrite/><ConfDataSet max="10"/></Services>
    <AccessPoint name="S1">
      <Server><Authentication/>
        <LDevice inst="PROT">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DOI name="Mod"><DAI name="stVal"><Val>on</Val></DAI><DAI name="ctlModel"><Val>status-only</Val></DAI></DOI>
            <DOI name="NamPlt"><DAI name="vendor"><Val>Demo</Val></DAI><DAI name="swRev"><Val>1.0</Val></DAI><DAI name="configRev"><Val>R1</Val></DAI></DOI>
            <DataSet name="DS_TRIP"><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Str" daName="general" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Str" daName="q" fc="ST"/></DataSet>
            <DataSet name="DS_POS"><FCDA ldInst="PROT" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" fc="ST"/><FCDA ldInst="PROT" prefix="" lnClass="GGIO" lnInst="1" doName="AnIn1" fc="MX"/></DataSet>
            <GSEControl name="GCB_TRIP" type="GOOSE" appID="PROT_Q02_TRIP" datSet="DS_TRIP" confRev="1"/>
            
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_T"><DOI name="PhyNam"><DAI name="vendor"><Val>Demo Vendor</Val></DAI><DAI name="model"><Val>Demo Model</Val></DAI></DOI></LN>
          <LN lnClass="PTRC" inst="1" prefix="" lnType="PTRC_T"/>
          <LN lnClass="XCBR" inst="1" prefix="" lnType="XCBR_T"><DOI name="Pos"><DAI name="stVal"><Val>on</Val></DAI></DOI></LN>
          <LN lnClass="GGIO" inst="1" prefix="" lnType="GGIO_T"><DOI name="AnIn1"><SDI name="mag"><DAI name="f"><Val>12.5</Val></DAI></SDI></DOI></LN>
          <LN lnClass="LGOS" inst="1" prefix="" lnType="LGOS_T"><DOI name="GoCBRef"><DAI name="setSrcRef"><Val>CTRL_Q01CTRL/LLN0.GCB_ILOCK</Val></DAI></DOI></LN>
          <LN lnClass="LSVS" inst="1" prefix="" lnType="LSVS_T"><DOI name="SvCBRef"><DAI name="setSrcRef"><Val>MU_Q01MU/LLN0.MSVCB01</Val></DAI></DOI></LN>
          <LN lnClass="GGIO" inst="1" prefix="GSE" lnType="GSEGGIO_T"/>
          <LN lnClass="GGIO" inst="2" prefix="" lnType="GGIO_T">
            <Inputs>
              <ExtRef iedName="CTRL_Q01" ldInst="CTRL" prefix="" lnClass="CILO" lnInst="1" doName="EnaOpn" daName="stVal" serviceType="GOOSE" srcLDInst="CTRL" srcCBName="GCB_ILOCK" intAddr="Ilock"/>
              <ExtRef iedName="MU_Q01" ldInst="MU" prefix="" lnClass="TCTR" lnInst="1" doName="AmpSv" serviceType="SMV" srcLDInst="MU" srcCBName="MSVCB01" intAddr="IA"/>
              <ExtRef iedName="CTRL_Q01" ldInst="CTRL" prefix="" lnClass="CSWI" lnInst="1" doName="Pos" daName="stVal" serviceType="GOOSE" srcLDInst="CTRL" srcCBName="GCB_MISSING" intAddr="Bad"/>
            </Inputs>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  
  <IED name="MU_Q01" type="DemoMU" manufacturer="DemoVendor" configVersion="1.0" desc="Merging unit Q01">
    <Services><GOOSE max="8"/><GSESettings/><SMVSettings/><GetDirectory/><GetDataObjectDefinition/><DataObjectDirectory/><GetDataSetValue/><DataSetDirectory/><ReadWrite/><ConfDataSet max="10"/></Services>
    <AccessPoint name="S1">
      <Server><Authentication/>
        <LDevice inst="MU">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DOI name="Mod"><DAI name="stVal"><Val>on</Val></DAI><DAI name="ctlModel"><Val>status-only</Val></DAI></DOI>
            <DOI name="NamPlt"><DAI name="vendor"><Val>Demo</Val></DAI><DAI name="swRev"><Val>1.0</Val></DAI><DAI name="configRev"><Val>R1</Val></DAI></DOI>
            <DataSet name="PhsMeas1"><FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="1" doName="AmpSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="2" doName="AmpSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="3" doName="AmpSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="4" doName="AmpSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="1" doName="VolSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="2" doName="VolSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="3" doName="VolSv" fc="MX"/><FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="4" doName="VolSv" fc="MX"/></DataSet>
            <SampledValueControl name="MSVCB01" smvID="MU_Q01_SV01" datSet="PhsMeas1" confRev="1" smpRate="80" nofASDU="1" multicast="true"><SmvOpts refreshTime="false" sampleSynchronized="true" sampleRate="false"/></SampledValueControl>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LPHD_T"><DOI name="PhyNam"><DAI name="vendor"><Val>Demo Vendor</Val></DAI><DAI name="model"><Val>Demo Model</Val></DAI></DOI></LN>
          <LN lnClass="TCTR" inst="1" prefix="" lnType="TCTR_T"/><LN lnClass="TCTR" inst="2" prefix="" lnType="TCTR_T"/><LN lnClass="TCTR" inst="3" prefix="" lnType="TCTR_T"/><LN lnClass="TCTR" inst="4" prefix="" lnType="TCTR_T"/><LN lnClass="TVTR" inst="1" prefix="" lnType="TVTR_T"/><LN lnClass="TVTR" inst="2" prefix="" lnType="TVTR_T"/><LN lnClass="TVTR" inst="3" prefix="" lnType="TVTR_T"/><LN lnClass="TVTR" inst="4" prefix="" lnType="TVTR_T"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <IED name="PMS_CI868" type="CI868" manufacturer="ABB" configVersion="1.0" desc="AC 800M power management – CI868 module 1">
    <Services><GOOSE max="64"/><GSESettings/><GetDirectory/><GetDataObjectDefinition/><DataObjectDirectory/><GetDataSetValue/><DataSetDirectory/><ReadWrite/><ConfDataSet max="10"/><ClientServices goose="true" bufReport="true" unbufReport="true"/></Services>
    <AccessPoint name="S1">
      <Server><Authentication/>
        <LDevice inst="PMS">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_T">
            <DOI name="Mod"><DAI name="stVal"><Val>on</Val></DAI></DOI>
            <DataSet name="DS_LS"><FCDA ldInst="PMS" prefix="LS" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/><FCDA ldInst="PMS" prefix="LS" lnClass="GGIO" lnInst="1" doName="Ind1" daName="q" fc="ST"/></DataSet>
            <GSEControl name="GCB_LS" type="GOOSE" appID="PMS_LOADSHED" datSet="DS_LS" confRev="1"/>
          </LN0>
          <LN lnClass="LPHD" inst="1" prefix="" lnType="LPHD_T"/>
          <LN lnClass="GGIO" inst="1" prefix="LS" lnType="GGIO_T"/>
          <LN lnClass="GGIO" inst="2" prefix="IN" lnType="GGIO_T">
            <Inputs>
              <ExtRef iedName="PROT_Q01" ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcCBName="GCB_TRIP" intAddr="Q01_TRIP"/>
              <ExtRef iedName="CTRL_Q01" ldInst="CTRL" prefix="" lnClass="CILO" lnInst="1" doName="EnaOpn" daName="stVal" serviceType="GOOSE" srcLDInst="CTRL" srcCBName="GCB_ILOCK" intAddr="Q01_ILOCK"/>
            </Inputs>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="ENC_Mod"/><DO name="Beh" type="ENS_Beh"/><DO name="Health" type="ENS_Health"/><DO name="NamPlt" type="LPL_T"/></LNodeType>
    <LNodeType id="LPHD_T" lnClass="LPHD"><DO name="PhyNam" type="DPL_T"/><DO name="PhyHealth" type="ENS_Health"/><DO name="Proxy" type="SPS_T"/><DO name="Sim" type="SPC_T"/></LNodeType>
    <LNodeType id="PTRC_T" lnClass="PTRC"><DO name="Beh" type="ENS_Beh"/><DO name="Str" type="ACD_T"/><DO name="Op" type="ACT_T"/><DO name="Tr" type="ACT_T"/></LNodeType>
    <LNodeType id="XCBR_T" lnClass="XCBR"><DO name="Beh" type="ENS_Beh"/><DO name="Pos" type="DPC_T"/><DO name="BlkOpn" type="SPC_T"/><DO name="BlkCls" type="SPC_T"/></LNodeType>
    <LNodeType id="CSWI_T" lnClass="CSWI"><DO name="Beh" type="ENS_Beh"/><DO name="Pos" type="DPC_T"/></LNodeType>
    <LNodeType id="CILO_T" lnClass="CILO"><DO name="Beh" type="ENS_Beh"/><DO name="EnaOpn" type="SPS_T"/><DO name="EnaCls" type="SPS_T"/></LNodeType>
    <LNodeType id="GGIO_T" lnClass="GGIO"><DO name="Beh" type="ENS_Beh"/><DO name="Ind1" type="SPS_T"/><DO name="AnIn1" type="MV_T"/></LNodeType>
    <LNodeType id="TCTR_T" lnClass="TCTR"><DO name="Beh" type="ENS_Beh"/><DO name="AmpSv" type="SAV_I"/></LNodeType>
    <LNodeType id="TVTR_T" lnClass="TVTR"><DO name="Beh" type="ENS_Beh"/><DO name="VolSv" type="SAV_I"/></LNodeType>
    <LNodeType id="LGOS_T" lnClass="LGOS"><DO name="Beh" type="ENS_Beh"/><DO name="St" type="SPS_T"/><DO name="SimSt" type="SPS_T"/><DO name="LastStNum" type="INS_T"/><DO name="ConfRevNum" type="INS_T"/><DO name="RxConfRevNum" type="INS_T"/><DO name="GoCBRef" type="ORG_T"/></LNodeType>
    <LNodeType id="GSEGGIO_T" lnClass="GGIO"><DO name="Beh" type="ENS_Beh"/><DO name="Alm" type="SPS_T"/><DO name="IntIn1" type="INS_T"/><DO name="IntIn2" type="INS_T"/><DO name="IntIn3" type="INS_T"/><DO name="IntIn4" type="INS_T"/><DO name="IntIn5" type="INS_T"/><DO name="IntIn6" type="INS_T"/><DO name="IntIn7" type="INS_T"/><DO name="IntIn8" type="INS_T"/><DO name="IntIn9" type="INS_T"/><DO name="IntIn10" type="INS_T"/></LNodeType>
    <LNodeType id="LSVS_T" lnClass="LSVS"><DO name="Beh" type="ENS_Beh"/><DO name="St" type="SPS_T"/><DO name="SimSt" type="SPS_T"/><DO name="ConfRevNum" type="INS_T"/><DO name="RxConfRevNum" type="INS_T"/><DO name="SvCBRef" type="ORG_T"/></LNodeType>
    <DOType id="INS_T" cdc="INS"><DA name="stVal" bType="INT32" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/></DOType>
    <DOType id="ORG_T" cdc="ORG"><DA name="setSrcRef" bType="ObjRef" fc="SP" dchg="true"/></DOType>
    <DOType id="ENC_Mod" cdc="ENC"><DA name="stVal" bType="Enum" type="Beh" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/><DA name="ctlModel" bType="Enum" type="CtlModels" fc="CF"/></DOType>
    <DOType id="ENS_Beh" cdc="ENS"><DA name="stVal" bType="Enum" type="Beh" fc="ST" dchg="true"><Val>on</Val></DA><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/></DOType>
    <DOType id="ENS_Health" cdc="ENS"><DA name="stVal" bType="Enum" type="Health" fc="ST" dchg="true"><Val>Ok</Val></DA><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/></DOType>
    <DOType id="LPL_T" cdc="LPL"><DA name="vendor" bType="VisString255" fc="DC"/><DA name="swRev" bType="VisString255" fc="DC"/><DA name="d" bType="VisString255" fc="DC"/><DA name="configRev" bType="VisString255" fc="DC"/><DA name="ldNs" bType="VisString255" fc="EX"><Val>IEC 61850-7-4:2007</Val></DA></DOType>
    <DOType id="DPL_T" cdc="DPL"><DA name="vendor" bType="VisString255" fc="DC"/><DA name="model" bType="VisString255" fc="DC"/><DA name="serNum" bType="VisString255" fc="DC"/></DOType>
    <DOType id="SPS_T" cdc="SPS"><DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/></DOType>
    <DOType id="ACT_T" cdc="ACT"><DA name="general" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="phsA" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="phsB" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="phsC" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/></DOType>
    <DOType id="ACD_T" cdc="ACD"><DA name="general" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="dirGeneral" bType="Enum" type="FaultDir" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/></DOType>
    <DOType id="DPC_T" cdc="DPC"><DA name="stVal" bType="Dbpos" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/><DA name="ctlModel" bType="Enum" type="CtlModels" fc="CF"><Val>status-only</Val></DA></DOType>
    <DOType id="SPC_T" cdc="SPC"><DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/><DA name="q" bType="Quality" fc="ST" qchg="true"/><DA name="t" bType="Timestamp" fc="ST"/><DA name="ctlModel" bType="Enum" type="CtlModels" fc="CF"><Val>status-only</Val></DA></DOType>
    <DOType id="MV_T" cdc="MV"><DA name="mag" bType="Struct" type="AnalogueValue_F" fc="MX" dchg="true"/><DA name="q" bType="Quality" fc="MX" qchg="true"/><DA name="t" bType="Timestamp" fc="MX"/></DOType>
    <DOType id="SAV_I" cdc="SAV"><DA name="instMag" bType="Struct" type="AnalogueValue_I" fc="MX"/><DA name="q" bType="Quality" fc="MX" qchg="true"/></DOType>
    <DAType id="AnalogueValue_F"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="AnalogueValue_I"><BDA name="i" bType="INT32"/></DAType>
    <EnumType id="Beh"><EnumVal ord="1">on</EnumVal><EnumVal ord="2">blocked</EnumVal><EnumVal ord="3">test</EnumVal><EnumVal ord="4">test/blocked</EnumVal><EnumVal ord="5">off</EnumVal></EnumType>
    <EnumType id="Health"><EnumVal ord="1">Ok</EnumVal><EnumVal ord="2">Warning</EnumVal><EnumVal ord="3">Alarm</EnumVal></EnumType>
    <EnumType id="CtlModels"><EnumVal ord="0">status-only</EnumVal><EnumVal ord="1">direct-with-normal-security</EnumVal><EnumVal ord="2">sbo-with-normal-security</EnumVal><EnumVal ord="3">direct-with-enhanced-security</EnumVal><EnumVal ord="4">sbo-with-enhanced-security</EnumVal></EnumType>
    <EnumType id="FaultDir"><EnumVal ord="0">unknown</EnumVal><EnumVal ord="1">forward</EnumVal><EnumVal ord="2">backward</EnumVal><EnumVal ord="3">both</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>
