using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace BizTalk.PipelineComponents.SecureEnvelope
{
    public static class Extensions
    {
        public static bool CheckedReadToFollowing(this XmlReader reader,string name)
        {
            if (reader.Name != name)
                return reader.ReadToFollowing(name);

            return true;
        }

        public static bool CheckedReadToFollowing(this XmlReader reader, string localName,string namespaceURI)
        {
            if (reader.LocalName == localName && (reader.NamespaceURI == namespaceURI || String.IsNullOrEmpty(namespaceURI)))
                return reader.ReadToFollowing(localName, namespaceURI);

            return true;
        }
    }
}
