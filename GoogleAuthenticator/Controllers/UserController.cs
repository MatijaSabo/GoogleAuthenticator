using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Text;
using GoogleAuthenticator.Models;
using Google.Authenticator;

namespace GoogleAuthenticator.Controllers
{
    public class UserController : Controller
    {
        [HttpGet]
        public ActionResult Registration()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude = "PrivateKey,KeyFlag")]User user)
        {
            bool Status = false;
            string message = "";

            #region Validacija
            if (ModelState.IsValid)
            {

                bool flag = UserNameExist(user.UserName);

                if (flag)
                {
                    message = "Username already exist";
                }
                else
                {
                    #region Password hash
                    user.Password = Crypto.Hash(user.Password);
                    user.ComfirmPassword = Crypto.Hash(user.ComfirmPassword);
                    #endregion

                    #region Google key
                    user.KeyFlag = false;

                    StringBuilder sb = new StringBuilder();
                    sb.Append(user.UserName).Append(user.Email);

                    user.PrivateKey = Crypto.Hash(sb.ToString());
                    #endregion

                    #region Database save
                    using (MyDatabaseEntities dc = new MyDatabaseEntities())
                    {
                        dc.Users.Add(user);
                        dc.SaveChanges();

                        message = "Registration successfully done.";
                        Status = true;
                    }
                    #endregion
                }
            }
            else
            {
                message = "Invalid request";
            }
            #endregion

            ViewBag.Message = message;
            ViewBag.Status = Status;

            return View(user);
        }

        [NonAction]
        public bool UserNameExist(String user)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.UserName == user).FirstOrDefault();
                return v == null ? false : true;
            }
        }

        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserLogin user)
        {
            string message = "";
            bool status = false;
            bool show_key = true;

            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.UserName == user.UserName).FirstOrDefault();
                if(v != null)
                {
                    if(String.Compare(Crypto.Hash(user.Password), v.Password) == 0)
                    {
                        status = true;
                        Session["username"] = user.UserName;

                        string key = v.PrivateKey;
                        Session["user_key"] = key;

                        if (v.KeyFlag == true)
                        {
                            show_key = false;
                        }

                        TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
                        var SetupInfo = tfa.GenerateSetupCode("SI Projekt", user.UserName, v.PrivateKey, 300, 300);
                        ViewBag.BarcodeImageUrl = SetupInfo.QrCodeSetupImageUrl;
                    }
                    else
                    {
                        message = "Invalid Password!";
                        ViewBag.FailLogin = true;
                    }
                } 
                else
                {
                    message = "Invalid Email address!";
                    ViewBag.FailLogin = true;
                }
            }

            ViewBag.Message = message;
            ViewBag.Status = status;
            ViewBag.QR_show = show_key;

            Session["show_key"] = show_key;

            return View();
        }

        public ActionResult Verify2FA()
        {
            var token = Request["passcode"];
            var key = Session["user_key"];
            var user = Session["username"];
            var show = Session["show_key"];

            TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
            bool isValid = tfa.ValidateTwoFactorPIN(key.ToString(), token);

            if (isValid)
            {
                Session["isValid2FA"] = true;

                if((Boolean) show == true)
                {
                    using (MyDatabaseEntities dc = new MyDatabaseEntities())
                    {

                        dc.Configuration.ValidateOnSaveEnabled = false;

                        var v = dc.Users.Where(a => a.UserName == user.ToString()).FirstOrDefault();

                        if (v != null)
                        {
                            v.KeyFlag = true;
                            dc.SaveChanges();
                        }

                    }
                }

                return RedirectToAction("ProfilePage", "User");
            }

            ViewBag.Message = "2FA Failed";
            return RedirectToAction("Login", "User");
        }


        public ActionResult ProfilePage()
        {
            if (Session["username"] == null || Session["isValid2FA"] == null || !(bool)Session["isValid2Fa"])
            {
                return RedirectToAction("Login");
            }

            ViewBag.Message = Session["username"].ToString();
            return View();
        }

        public ActionResult Logout()
        {
            Session["username"] = null;
            Session["isValid2FA"] = null;
            Session["user_key"] = null;
            Session["show_key"] = null;

            ViewBag.Status = false;
            ViewBag.Message = "Logout success";
            return RedirectToAction("Login", "User");
        }
    }
}