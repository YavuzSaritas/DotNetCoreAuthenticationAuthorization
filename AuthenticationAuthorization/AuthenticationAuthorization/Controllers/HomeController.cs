using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using AuthenticationAuthorization.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace AuthenticationAuthorization.Controllers
{
    public class HomeController : Controller
    {
        public HomeController()
        {
            
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        /*Policy Sağlamayan kullanıcalar giremez*/
        [Authorize(Policy = "Claim.DoB")]
        public IActionResult PrivacyPolicy()
        {
            return View("Privacy");
        }

        [Authorize(Roles= "Admin")]
        public IActionResult PrivacyRole()
        {
            return View("Privacy");
        }

        public IActionResult Authenticate()
        {
            /*Kimlik Doğrulama(Kimlik Cookie tutuluyor)*/
            /*burası kullanıcı giriş yaptıktan sonra Dbden gelen bilgilerle doldurulabilir*/

            /*Kimlik için Claimler oluşturulur.*/
            var userClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,"Yavuz"),
                new Claim(ClaimTypes.Email,"yavuz@deneme.com"),
                new Claim("Test.Claim","Heyyyy!!"),
                new Claim(ClaimTypes.DateOfBirth,"11/11/2000"),//Policy için doğum tarihi ekleniyor
                new Claim(ClaimTypes.Role,"Admin")
            };
            var licenseClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,"Ali"),
                new Claim("DrivingLicende","B")
            };

            /*Kimlik Oluşturuluyor*/
            var userIdentity = new ClaimsIdentity(userClaims, "User Identity");
            var licenseIdentity = new ClaimsIdentity(licenseClaims, "license Identity");

            /*UserPrincipal birden çok kimlik içerebilir. Google, Facebook gibi*/
            var userPrincipal = new ClaimsPrincipal(new[] { userIdentity,licenseIdentity });

            /*HttpContext'e bilgiler gönderilir*/
            HttpContext.SignInAsync(userPrincipal);

            return View("Index");
        }

    }
}
