#define KeyVault //switch to KeyVault or LocalCert 
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace DemoSSL
{
    public class Program
    {
        

        public static void Main(string[] args)
        {


            CreateHostBuilder(args).Build().Run();
        }
#if LocalCert
        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            X509Certificate2 _certificate = null;
            using (var store = new X509Store(StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                var certs = store.Certificates.Find(X509FindType.FindByThumbprint,
                    "D43EC4E6816F943CC219BED66360700ED2A928A7", false);
                if (certs.Count > 0)
                {
                    _certificate = certs[0];
                }
                else { throw new SecurityException("No SSL Certificate Found. Check your Store and Thumbprint. Please"); }
            };
            return Host.CreateDefaultBuilder(args)
                  .ConfigureWebHostDefaults(webBuilder =>
                  {
                      webBuilder.UseKestrel(
                          options => options.ListenAnyIP(443, listenOption =>
                         listenOption.UseHttps(_certificate)
                          ));
                      webBuilder.UseStartup<Startup>();
                  });
        }
    }
#endif
#if KeyVault
        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            X509Certificate2 _certificate = null;


            var kv = new KeyVaultClient(async (authority, resource, scope) =>
            {
                var authContext = new AuthenticationContext(authority);
                var clientCred = new ClientCredential("b726d3f3-1f9a-4dfd-a765-86f5b09bbd49", ".AW=Z58=UUiYTZVNrApp_ACfY92YR60p");
                var result = await authContext.AcquireTokenAsync(resource, clientCred);

                if (result == null)
                    throw new InvalidOperationException("Failed to obtain the JWT token");

                return result.AccessToken;
            });
            try
            {
                var certificateSecret = kv.GetSecretAsync($"https://vc2020kv.vault.azure.net/", "vc-demo-ssl").Result;
                var privateKeyBytes = Convert.FromBase64String(certificateSecret.Value);
                _certificate = new X509Certificate2(privateKeyBytes, (string)null);
            }
            catch (Exception)
            {

                throw new SecurityException("Can't get the cert from your KV, Please check your Key Vault URL and Cert name. Also how is your Access Policy? DID YOU CLICK SAVE?");
            }
          

            return Host.CreateDefaultBuilder(args)
                  .ConfigureWebHostDefaults(webBuilder =>
                  {
                      webBuilder.UseKestrel(
                          options => options.ListenAnyIP(443, listenOption =>
                         listenOption.UseHttps(_certificate)
                          ));
                      webBuilder.UseStartup<Startup>();
                  });
        }
    }
#endif


}
