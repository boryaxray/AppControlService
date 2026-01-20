using System;
using System.Linq;
using System.Runtime.Serialization;

namespace ApplicationControlService.Models
{
    [DataContract]
    public class WhiteListItem
    {
        [DataMember(Name = "Name")]
        public string Name { get; set; }

        [DataMember(Name = "Hash")]
        public string Hash { get; set; }  // SHA256 хэш (64 символа)

        public WhiteListItem() { }

        public WhiteListItem(string name, string hash)
        {
            Name = name;
            Hash = hash;
        }

        public bool IsValid()
        {
            return !string.IsNullOrWhiteSpace(Name) &&
                   !string.IsNullOrWhiteSpace(Hash) &&
                   Hash.Length == 64 &&
                   Hash.All(c => (c >= '0' && c <= '9') ||
                                 (c >= 'a' && c <= 'f') ||
                                 (c >= 'A' && c <= 'F'));
        }

        public override string ToString()
        {
            return $"{Name} ({Hash.Substring(0, 8)}...)";
        }
    }
}