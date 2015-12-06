/* MVRoleMaintenanceController.cs
 * Assignment 7
 * Revision History
 *      Matt Van Boxtel, 2015.11.28: Created
 *      Matt Van Boxtel, 2015.11.28: Completed
 */ 

using System;
using System.Collections.Generic;
using A4BusService.Models;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace A4BusService.Controllers
{
    [Authorize(Roles = "administrators")]
    public class MVUserMaintenanceController : Controller
    {
        public static ApplicationDbContext db = new ApplicationDbContext();
        private UserManager<ApplicationUser> userManager =
            new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(db));
        private RoleManager<IdentityRole> roleManager =
            new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));

        // GET: MVUserMaintenance
        // lists all users
        public ActionResult Index()
        {
            List<ApplicationUser> users = userManager.Users.OrderBy(v => v.UserName).ToList();
            return View(users);
        }

        // delete a user
        public ActionResult Delete(string userId)
        {
            // get the user object to delete
            ApplicationUser user = userManager.FindById(userId);

            try
            {
                // get result object of the delete of user from user manager
                IdentityResult result = userManager.Delete(user);
                if (result.Succeeded)
                {
                    TempData["message"] = "user deleted: " + user.UserName;
                }
                else
                {
                    TempData["message"] = "user not deleted " + result.Errors.ToList()[0];
                }
            }
            catch (Exception ex)
            {
                TempData["message"] = "delete user threw an exception: " + ex.GetBaseException().Message;
            }

            return RedirectToAction("Index");
        }

        // reset user password, called when "reset password" button is clicked beside user name
        public ActionResult ResetPassword(string userId)
        {
            // get user object that we want to change password of
            ApplicationUser user = userManager.FindById(userId);

            // if user is in administrators role, do not allow password reset
            if (userManager.IsInRole(user.Id, "administrators"))
            {
                TempData["message"] = "Cannot reset admin password";
                return RedirectToAction("Index");
            }

            ViewBag.email = user.Email;

            return View();
        }

        // reset password confirm, once entering new password twice identically reset the password
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ResetPassword(string userId, string password, string confirmPassword)
        {
            // get user object to reset password
            ApplicationUser user = userManager.FindById(userId);

            // if passwords do not match send user back to reset password screen
            if (!password.Equals(confirmPassword))
            {
                TempData["message"] = "Passwords do not match";
                return RedirectToAction("ResetPassword", userId);
            }

            try
            {
                // declare result
                IdentityResult identityResult;

                var provider = new Microsoft.Owin.Security.DataProtection.DpapiDataProtectionProvider("A4BusService");
                userManager.UserTokenProvider = new Microsoft.AspNet.Identity.Owin.DataProtectorTokenProvider<ApplicationUser>(provider.Create("PasswordReset"));

                // generate password reset token for security, needed for reset password
                string passwordToken = userManager.GeneratePasswordResetToken(userId);

                // call reset password from user manager for the result
                identityResult = userManager.ResetPassword(userId, passwordToken, password);

                // if result is successful send user to index, otherwise send back to reset password
                if (identityResult.Succeeded)
                {
                    TempData["message"] = "Password changed successfully";
                    return RedirectToAction("Index");
                }
                else
                {
                    TempData["message"] = "Password reset was unsuccessful: " + identityResult.Errors.ToList()[0];
                    return RedirectToAction("ResetPassword", userId);
                }
            }
            catch (Exception ex)
            {
                TempData["message"] = "Reset password exception: " + ex.GetBaseException().Message;
            }

            return RedirectToAction("Index");
        }

        // lock a user, disallowing them from logging in
        public ActionResult Lock(string userId)
        {
            // get user object
            ApplicationUser user = userManager.FindById(userId);
            try 
	        {	
                // if user is administrator disallow lock, otherwise lock user
		        if (userManager.IsInRole(user.Id, "administrators"))
	            {
		            user.LockoutEnabled = false;
                    TempData["message"] = "Cannot lock Admin account";
	            }
                else
	            {
                    user.LockoutEnabled = true;
                    user.LockoutEndDateUtc = null;
                    db.SaveChanges();
                    TempData["message"] = "User " + user.Email + " has been locked";
	            }
	        }
	        catch (Exception ex)
	        {
		        TempData["message"] = "Exception in user lock " + user.UserName + " " + ex.GetBaseException().Message;
	        }
            return RedirectToAction("Index");
        }

        // unlock a user, allowing them to log in
        public ActionResult Unlock(string userId)
        {
            // get user object
            ApplicationUser user = userManager.FindById(userId);
            try
            {
                // if user is administrator, disallow unlock, otherwise unlock user
                if (userManager.IsInRole(user.Id, "administrators"))
                {
                    user.LockoutEnabled = false;
                    TempData["message"] = "Cannot unlock Admin account";
                }
                else
                {
                    user.LockoutEnabled = false;
                    user.LockoutEndDateUtc = null;
                    db.SaveChanges();
                    TempData["message"] = "User " + user.Email + " has been unlocked";
                }
            }
            catch (Exception ex)
            {
                TempData["message"] = "Exception in user unlock " + user.UserName + " " + ex.GetBaseException().Message;
            }
            return RedirectToAction("Index");
        }
    }
}