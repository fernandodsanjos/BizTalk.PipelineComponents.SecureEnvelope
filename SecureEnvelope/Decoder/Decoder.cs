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
using System.Collections.Generic;
using System.Collections.Concurrent;

namespace BizTalk.PipelineComponents.SecureEnvelope
{
    [ComponentCategory(CategoryTypes.CATID_PipelineComponent)]
    [System.Runtime.InteropServices.Guid("fbf617f4-8013-49ed-b615-adb7577b8d6a")]
    [ComponentCategory(CategoryTypes.CATID_Decoder)]
    public partial class Decoder : IComponent, IBaseComponent, IComponentUI
    {
        const string BTS = "http://schemas.microsoft.com/BizTalk/2003/system-properties";
        const string SEC = "http://SecureEnvelope";
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
                return "Nordea Secure Envelope (1.2) Decoder";

            }
        }
        #endregion

        #region Properties
        [Description("Disable component")]
        [RequiredRuntime]
        public bool Disable { get; set; } = false;

        [Description("Validate Signature")]
        public bool Verify { get; set; } = false;

        [Description("Used when validating signature")]
        public string Thumbprint { get; set; }

        [Description("Used when validating signature")]
        [DisplayName("Previous Thumbprint")]
        public string PreviousThumbprint { get; set; }

        [Description("Pass original message on error")]
        [DisplayName("PassThru on error")]
        public bool PassThru { get; set; }
        private bool Compressed { get; set; } = false;

        private int ResponseCode { get; set; } = 0;

        private string ExecutionSerial { get; set; }

        private string InterchangeID { get; set; }

        

        private ConcurrentDictionary<string, X509Certificate2> Certificates { get; set; } = new ConcurrentDictionary<string, X509Certificate2>();
        #endregion
        public IBaseMessage Execute(IPipelineContext pContext, IBaseMessage pInMsg)
        {
           

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

                    pInMsg.Context.Promote("ResponseCode", SEC, (object)-1);

                    if (PromoteFault(pInMsg, $"Invalid bank Signature for message {InterchangeID} detected"))
                    {
                        return pInMsg;
                    }

                    
                   

                }
            }

            Stream outStm = null;

            using (XmlReader reader = XmlReader.Create(pInMsg.BodyPart.Data,new XmlReaderSettings { CloseInput = false }))
            {
                
                string responseText = String.Empty;

                // Get original Message Type
                reader.MoveToContent();
                pInMsg.Context.Promote("MessageType", BTS, $"{reader.NamespaceURI}#{reader.LocalName}");

               

                while (reader.Read())
                {
                    if(reader.IsStartElement())
                    {
                        bool nextElement = true; 

                        while (nextElement)
                        {
                            switch (reader.LocalName)
                            {
                                case "ResponseCode":
                                    ResponseCode = reader.ReadElementContentAsInt();

                                    pInMsg.Context.Promote("ResponseCode", SEC, (object)ResponseCode);

                                    break;
                                case "ResponseText":
                                    responseText = reader.ReadElementContentAsString();
                                    break;
                                case "ExecutionSerial":
                                    ExecutionSerial = reader.ReadElementContentAsString();

                                    pInMsg.Context.Write("ExecutionSerial", SEC, (object)ExecutionSerial);

                                    //If used with messsage Encoded with BizTalk.PipelineComponents.SecureEnvelope.Encoder
                                    if (ExecutionSerial.Length == 32)
                                    {
                                        var targetId = GetExecutionTargetId(ExecutionSerial);

                                        pInMsg.Context.Promote("SignerID", SEC, targetId);
                                    }

                                    break;
                                case "Compressed":
                                    Compressed = reader.ReadElementContentAsBoolean();
                                    break;
                                case "ParentFileReference":
                                    if (ExecutionSerial.Length != 32)
                                    {
                                        //new in v 1.2
                                        string signerId = reader.ReadElementContentAsString();

                                        if (signerId.Length > 1)
                                        {
                                            pInMsg.Context.Promote("SignerID", SEC, signerId);
                                        }

                                    }
                                    else
                                        nextElement = false;
                                    break;
                                case "Content":
                                    if (ResponseCode == 0 || PassThru == false)
                                    {
                                        reader.CheckedReadToFollowing("Content");

                                        outStm = Base64ElementToStream(reader);

                                        string messageType = GetmessageType(outStm);

                                        pInMsg.Context.Promote("MessageType", BTS, messageType);
                                    }
                                    else
                                        nextElement = false;
                                    break;
                                default:
                                    nextElement = false;
                                    break;
                            }
                        }
                      
                    }

                }

                if (ResponseCode > 0)
                {

                    if (PromoteFault(pInMsg, responseText))
                    {
                        pInMsg.BodyPart.Data.Position = 0;
                        return pInMsg;
                    }
                       
                }

                pContext.ResourceTracker.AddResource(outStm);
                pInMsg.BodyPart.Data = outStm;

            }

            return pInMsg;
        }

    

        private string GetmessageType(Stream message)
        {
            string messageType = String.Empty;

            using (XmlReader reader = XmlReader.Create(message, new XmlReaderSettings { IgnoreWhitespace = true, IgnoreComments = true, IgnoreProcessingInstructions = true }))
            {
                reader.MoveToContent();

                messageType = $"{reader.NamespaceURI}#{reader.LocalName}";
            }

            message.Position = 0;

            return messageType;
        }
        private bool PromoteFault(IBaseMessage pInMsg,string responseText)
        {
            
            pInMsg.Context.Promote("ResponseText", SEC, responseText);
         

            if (PassThru)
            {
                pInMsg.BodyPart.Data.Seek(0, SeekOrigin.Begin);
                return true;
            }

            return false;
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

            if (String.IsNullOrEmpty(Thumbprint))
                throw new ArgumentNullException("Thumbprint must be set to be able to verify signature!");

            cert = GetCertificate(Thumbprint);

            if (cert == null && PreviousThumbprint?.TrimEnd()?.Length > 0)
            {
                cert = GetCertificate(PreviousThumbprint);
            }
                
            if (cert == null)
                throw new Exception($"Certificate with specified Thumbprint(s) {Thumbprint},{PreviousThumbprint} could not be found!");

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

        private X509Certificate2 GetCertificate(string thumbprint)
        {
           
            X509Certificate2 cert = null;
            thumbprint = thumbprint.ToLower();

            if (Certificates.TryGetValue(thumbprint,out cert) == false)
            {
                using (X509Store certStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine))
                {
                    certStore.Open(OpenFlags.ReadOnly);

                    X509Certificate2Collection certCollection = certStore.Certificates.Find(
                        X509FindType.FindByThumbprint, thumbprint, false);

                    if (certCollection.Count > 0)
                    {
                        cert = certCollection[0];
                        Certificates.TryAdd(thumbprint, cert);

                    }

                }
            }

            return cert;

        }
        private  Stream Base64ElementToStream(XmlReader reader)
        {

            VirtualStream baseStm = new VirtualStream();

            byte[] buffer = new byte[8192];
            int readBytes = 0;

                while ((readBytes = reader.ReadElementContentAsBase64(buffer, 0, buffer.Length)) > 0)
                {
                    baseStm.Write(buffer, 0, readBytes);
                }

            baseStm.Position = 0;

            if(Compressed)
            {
                VirtualStream decompressedMemStream = new VirtualStream();
                GZipStream gzipStream = new GZipStream(baseStm, CompressionMode.Decompress);
                gzipStream.CopyTo(decompressedMemStream);
                decompressedMemStream.Position = 0;

                return decompressedMemStream;
            }
            else
            {
                return baseStm;
            }
 
        }

        private void LogEvent(string message,Exception exception = null)
        {
            EventLog.WriteEntry("BizTalk", $"SecureEnvelope failed to decode message with InterchangeId {InterchangeID} \n {message} \n {exception?.Message}");
        }

       

    }
}
