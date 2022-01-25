using BizTalkComponents.Utils;
using Microsoft.BizTalk.Component.Interop;
using Microsoft.BizTalk.Message.Interop;
using Microsoft.BizTalk.Streaming;
using System;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.XPath;
using System.Diagnostics;
using System.Security.Cryptography;
using IComponent = Microsoft.BizTalk.Component.Interop.IComponent;

namespace BizTalk.PipelineComponents.SecureEnvelope
{
    [ComponentCategory(CategoryTypes.CATID_PipelineComponent)]
    [System.Runtime.InteropServices.Guid("fbf617f4-8013-49ed-b615-adb7577b8d6a")]
    [ComponentCategory(CategoryTypes.CATID_Decoder)]
    public partial class Decoder : IComponent, IBaseComponent, IComponentUI
    {
        const string BTS = "http://schemas.microsoft.com/BizTalk/2003/system-properties";
        #region Name & Description

        public string Name
        {
            get
            {
                return "Secure Envelope Decoder";

            }
        }

        public string Version { get { return "1.0"; } }


        public string Description
        {
            get
            {
                return "Nordea Secure Envelope Decoder";

            }
        }
        #endregion

        #region Properties
        [Description("Disable component")]
        [RequiredRuntime]
        public bool Disable { get; set; } = false;

        [Description("Validate Signature")]
        public bool Verify { get; set; } = false;

        private bool Compressed { get; set; } = false;

        private int ResponseCode { get; set; } = 0;

        private string ExecutionSerial { get; set; }

        private string InterchangeID { get; set; }

       
        #endregion
        public IBaseMessage Execute(IPipelineContext pContext, IBaseMessage pInMsg)
        {
            Stream outStm = null;

            if (Disable)
                return pInMsg;

            if(pInMsg?.BodyPart?.Data == null)
                return pInMsg;

            InterchangeID = (string)pInMsg.Context.Read("InterchangeID", BTS);


            if (Verify)
            {
                bool valid = CheckSignature(pInMsg.BodyPart.Data);

                if (valid == false)
                {
                    throw new CryptographicException($"Invalid bank Signature for message {InterchangeID} detected");
                }
            }

            using (XmlReader reader = XmlReader.Create(pInMsg.BodyPart.Data))
            {

                reader.CheckedReadToFollowing("ResponseCode");
                ResponseCode = reader.ReadElementContentAsInt();

                if(ResponseCode > 0)
                {
                    reader.CheckedReadToFollowing("ResponseText");
                    string responseText = reader.ReadElementContentAsString();

                    pInMsg.Context.Promote("FaultName", BTS, responseText);
                }

               

                reader.CheckedReadToFollowing("ExecutionSerial");
                ExecutionSerial = reader.ReadElementContentAsString();

                if(ExecutionSerial.Length == 32)
                {
                    var targetId = GetExecutionTargetId(ExecutionSerial);
                   
                    pInMsg.Context.Promote("DestinationParty", BTS, targetId);
                }


                reader.CheckedReadToFollowing("Compressed");
                Compressed = reader.ReadElementContentAsBoolean();

                reader.CheckedReadToFollowing("Content");

                outStm = Base64ElementToStream(reader);

                pInMsg.BodyPart.Data = outStm;

            }

            return pInMsg;
        }

        private string GetExecutionTargetId(string executionSerial)
        {
            return UInt64.Parse(executionSerial.Substring(20)).ToString();
        }

        private bool CheckSignature(Stream signedMessage)
        {
            bool valid = false;
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(signedMessage);
            SignedXml signedXml = new SignedXml(xmlDoc);
            X509Certificate2 cert = null;


            XmlNodeList certTags = xmlDoc.GetElementsByTagName("X509Certificate", "http://www.w3.org/2000/09/xmldsig#");

            if(certTags.Count == 0)
                 certTags = xmlDoc.GetElementsByTagName("X509Certificate");

            XmlElement certTag = null;

            if (certTags.Count == 0)
            {
                LogEvent("Element X509Certificate is missing in message");
            }
            else
                certTag = (XmlElement)certTags[0];

            XmlNodeList signatureList = xmlDoc.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");

            if (signatureList.Count == 0)
            {
                signatureList = xmlDoc.GetElementsByTagName("Signature");
            }

            XmlElement signature = null;

            if (signatureList.Count == 0)
            {
                LogEvent("Element Signature is missing in message");
            }
                signature = (XmlElement)signatureList[0];

            try
            {
                Byte[] rawData = Convert.FromBase64String(certTag.InnerText);
                cert = new X509Certificate2(rawData);
            }
            catch (CryptographicException ex)
            {
                LogEvent("Unable to load X509Certificate",ex);
            }

            signedXml.LoadXml(signature);
            signedMessage.Position = 0;

            try
            {
                valid = signedXml.CheckSignature(cert.PublicKey.Key);
            }
            catch (CryptographicException ex)
            {
                LogEvent("Unable to check signature", ex);
            }
            return valid;

        }
        private  Stream Base64ElementToStream(XmlReader reader)
        {
            VirtualStream outStm = new VirtualStream();

            byte[] buffer = new byte[8192];
            int readBytes = 0;

                while ((readBytes = reader.ReadElementContentAsBase64(buffer, 0, buffer.Length)) > 0)
                {
                    outStm.Write(buffer, 0, readBytes);
                }

            outStm.Position = 0;

            if(Compressed)
            {
                GZipStream zipStream = new GZipStream(outStm, CompressionMode.Decompress);
                return zipStream;
            }
            else
            {
                return outStm;
            }
 
        }

        private void LogEvent(string message,Exception exception = null)
        {
            EventLog.WriteEntry("BizTalk", $"SecureEnvelope failed to decode message with InterchangeId {InterchangeID} \n {message} \n {exception?.Message}");
        }

       

    }
}
