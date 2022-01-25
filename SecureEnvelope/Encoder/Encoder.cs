using BizTalkComponents.Utils;
using Microsoft.BizTalk.Component.Interop;
using Microsoft.BizTalk.Message.Interop;
using Microsoft.BizTalk.Streaming;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using IComponent = Microsoft.BizTalk.Component.Interop.IComponent;
using System.IO.Compression;
using System.Configuration;
using System.Diagnostics;

namespace BizTalk.PipelineComponents.SecureEnvelope
{
    [ComponentCategory(CategoryTypes.CATID_PipelineComponent)]
    [System.Runtime.InteropServices.Guid("fbf617f4-8013-49ed-b615-adb7577b8d6d")]
    [ComponentCategory(CategoryTypes.CATID_Encoder)]
    public partial class Encoder : IComponent, IBaseComponent, IComponentUI
    {
        #region Name & Description

        public string Name
        {

            get
            {
                return "Secure Envelope Encoder";

            }
        }

        public string Version { get { return "1.0"; } }


        public string Description
        {
            get
            {
                return "Nordea Secure Envelope Encoder";

            }
        }
        #endregion

        #region Properties
        [Description("Disable component")]
        [RequiredRuntime]
        public bool Disable { get; set; } = false;

        [IntegerValidator(MinValue = 1, MaxValue = 16)]
        public UInt64 CustomerId { get; set; }
        public string Environment { get; set; }


        [RegularExpression(@"^[0-9]{1,80}$", ErrorMessage = "Max number is 80")]
        public string TargetId { get; set; }

        [Description("If TargetId is longer then 12 numbers, then InternalTargetId is used when calculating ExecutionSerial")]
        [IntegerValidator(MinValue = 1, MaxValue = 12)]
        public UInt64 InternalTargetId { get; set; }

        public bool Compress { get; set; }
        public string SoftwareId { get; set; }
        public string FileType { get; set; }

        
        public string CertificateThumbprint { get; set; }
        
        #endregion

        private string InterchangeID { get; set; }

        public IBaseMessage Execute(IPipelineContext pContext, IBaseMessage pInMsg)
        {
            if (Disable)
                return pInMsg;

            if (pInMsg?.BodyPart?.Data == null)
                return pInMsg;
            //Use VirtualStream when handling streams
            //ContextProperty prop = new ContextProperty(Property);

            //object value = pInMsg.Context.Read(prop);
            /*
             <CustomerId>7723525704</CustomerId>
            <Command>UPLOADFILE</Command>
            <Timestamp>2022-01-18T14:22:13.165+01:00</Timestamp>
            <Environment>PRODUCTION</Environment>
            <TargetId>13400338291</TargetId>
            <ExecutionSerial>12345</ExecutionSerial>
            <Compression>true</Compression>
            <CompressionMethod>GZIP</CompressionMethod>
            <SoftwareId>FS Technology AB SecureEnvelope 1.1.0</SoftwareId>
            <FileType>NDCAPXMLI</FileType>
            */

            IBaseMessagePart bodyPart = pInMsg?.BodyPart;

            
            InterchangeID = (string)pInMsg.Context.Read("InterchangeID", "http://schemas.microsoft.com/BizTalk/2003/system-properties");

            try
            {
               

                string userFileName = Path.GetFileName(pInMsg.Context.Read("ReceivedFileName", "http://schemas.microsoft.com/BizTalk/2003/file-properties").ToString());

                //StreamReader sr = new StreamReader(bodyPart.Data);
                VirtualStream incomingmemorystream = new VirtualStream();
                MemoryStream outgoingmemorystream = new MemoryStream();

                //sr.BaseStream.CopyTo(incomingmemorystream);
                //incomingmemorystream.Position = 0;

                bodyPart.Data.Position = 0;

                if (Convert.ToBoolean(Compress))
                {
                    using (GZipStream gzipStream = new GZipStream(outgoingmemorystream, CompressionMode.Compress))
                    {

                        bodyPart.Data.CopyTo(gzipStream); 
                    }
     
                }
                else
                {
                    bodyPart.Data.CopyTo(outgoingmemorystream);
                }
                    
                byte[] bytebodypart = outgoingmemorystream.ToArray();

                string fileasbase64 = Convert.ToBase64String(bytebodypart);

                string executionSerial = CreateExecutionSerial();
                //Used for correlation between this request and its response
                //pInMsg.Context.Write("ExecutionSerial", Namespace, executionSerial);

                // byte[] secureenv
                Stream secureenvstream = CreateSecureEnvelope(fileasbase64, userFileName, executionSerial, CertificateThumbprint);
                // MemoryStream secureenvstream = new MemoryStream(secureenv);
                // secureenvstream.Position = 0;

                bodyPart.Data = secureenvstream;
            }
            catch (System.Exception ex)
            {
                throw ex;
            }
            

            return pInMsg;
        }

        private string CreateExecutionSerial()
        {
            UInt64 targetId = 0;

            if (TargetId.Length > 12)
            {
                targetId = InternalTargetId;
            }
            else
            {
                targetId = UInt64.Parse(TargetId);
            }

            var dt = DateTime.Now.ToString("yyyyMMddHHmmssfff");

            var random = new Random();
            int randomnumber = random.Next(1, 999);

            return $"{DateTime.Now.ToString("yyyyMMddHHmmssfff")}{randomnumber}{targetId.ToString("000000000000")}";
        }
        public Stream CreateSecureEnvelope(string content, string userFileName, string executionSerial, string certificateThumbprint)
        {
            VirtualStream outstm = new VirtualStream();
            DateTime currentDate = DateTime.Now;
            string currentdatestring = currentDate.ToString("yyyy-MM-ddThh:mm:ss.fffzzz");
            XmlDocument secureenvelope = new XmlDocument();
            secureenvelope.LoadXml($@"<ApplicationRequest xmlns='http://bxd.fi/xmldata/'>
                        <CustomerId>{SecurityElement.Escape(CustomerId.ToString())}</CustomerId>
                        <Command>UploadFile</Command>
                        <Timestamp>{SecurityElement.Escape(currentdatestring)}</Timestamp>
                        <Environment>{SecurityElement.Escape(Environment)}</Environment>
                        <UserFilename>{SecurityElement.Escape(userFileName)}</UserFilename>
                        <TargetId>{SecurityElement.Escape(TargetId)}</TargetId>
                        <ExecutionSerial>{SecurityElement.Escape(executionSerial)}</ExecutionSerial>
                        <Compression>{SecurityElement.Escape(Compress.ToString().ToLower())}</Compression>
                        <CompressionMethod>GZIP</CompressionMethod>
                        <SoftwareId>{SecurityElement.Escape(SoftwareId)}</SoftwareId>
                        <FileType>{SecurityElement.Escape(FileType)}</FileType>
                        <Content>{content}</Content>
                    </ApplicationRequest>
                    ");



            XmlDocument signedsecureenvelope = SignXmlEnvelope(secureenvelope, certificateThumbprint);

            signedsecureenvelope.Save(outstm);
            outstm.Position = 0;
            //byte[] retvaluebytes = Encoding.UTF8.GetBytes(signedsecureenvelope.OuterXml);

            return outstm;

        }

        public XmlDocument SignXmlEnvelope(XmlDocument sourcedoc, string certificateThumbprint)
        {
            X509Certificate2 cert = new X509Certificate2();
            cert = GetCertificate(certificateThumbprint);

            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key = (RSACryptoServiceProvider)cert.PrivateKey;

            SignedXml signedXml = new SignedXml(sourcedoc);
            signedXml.SigningKey = key;

            Signature XMLSignature = signedXml.Signature;

            Reference reference = new Reference("");

            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            XMLSignature.SignedInfo.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyData = new KeyInfoX509Data();
            keyData.AddIssuerSerial(cert.IssuerName.Name.ToString(), cert.GetSerialNumberString());
            keyData.AddCertificate(cert);
            keyInfo.AddClause(keyData);

            XMLSignature.KeyInfo = keyInfo;

            signedXml.ComputeSignature();
           
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            sourcedoc.DocumentElement.AppendChild(sourcedoc.ImportNode(xmlDigitalSignature, true));

            /*
            if (sourcedoc.FirstChild is XmlDeclaration)
            {
                sourcedoc.RemoveChild(sourcedoc.FirstChild);
            }
            */

            return sourcedoc;
        }

        public X509Certificate2 GetCertificate(string certificateThumbprint)
        {
            X509Store localStore = new X509Store(StoreLocation.LocalMachine);

            localStore.Open(OpenFlags.ReadOnly);
            RSACryptoServiceProvider csp = null;
            X509Certificate2 x509cert = null;

            foreach (X509Certificate2 cert in localStore.Certificates)
            {
                if (cert.Thumbprint.Replace("-", "").ToUpper() == certificateThumbprint.Replace("-", "").ToUpper())
                {
                    csp = (RSACryptoServiceProvider)cert.PrivateKey;
                    x509cert = cert;
                    break;
                }
            }

            if (csp == null)
            {
                throw new Exception($"BizTalk.PipelineComponents.SecureEnvelope.Encoder. Certificate {certificateThumbprint} coud not be found!");
            }

            return x509cert;
        }

        private void LogEvent(string message, Exception exception = null)
        {
            EventLog.WriteEntry("BizTalk", $"SecureEnvelope failed to encode message with InterchangeId {InterchangeID} \n {message} \n {exception?.Message}");
        }

    }
}
