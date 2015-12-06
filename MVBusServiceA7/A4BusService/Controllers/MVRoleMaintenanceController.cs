/* MVRoleMaintenanceController.cs
 * Assignment 7
 * Revision History
 *      Matt Van Boxtel, 2015.11.28: Created
 *      Matt Van Boxtel, 2015.11.28: Completed
 */ 

using A4BusService.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace A4BusService.Controllers
{
    [Authorize(Roles = "administrators")]
    public class MVRoleMaintenanceController : Controller
    {
        public static ApplicationDbContext db = new ApplicationDbContext();
        private UserManager<ApplicationUser> userManager =
            new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(db));
        private RoleManager<IdentityRole> roleManager =
            new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(db));
        // GET: MVRoleMaintenance
        // list all roles
        public ActionResult Index()
        {
            List<IdentityRole> roles = roleManager.Roles.OrderBy(a => a.Name).ToList();
            return View(roles);
        }

        // add a new role, if role name does not exist
        public ActionResult AddRole(string roleName)
        {
            // if role name exists, do not allow user to create role, otherwise delete role
            if (roleName == null || roleName.Trim() == "" || roleManager.RoleExists(roleName))
            {
                TempData["message"] = "please specify a non-blank role name that's not already on file";
            }
            else
            {
                try
                {
                    // create result object from rolemanager create with the identity role name as role name
                    IdentityResult result = roleManager.Create(new IdentityRole(roleName.Trim()));
                    // if result succeeded send message with role name added, otherwise show errors
                    if (result.Succeeded)
                    {
                        TempData["message"] = "role added: " + roleName;
                    }
                    else
                    {
                        TempData["message"] = "role not added: " + result.Errors.ToList()[0];
                    }
                }
                catch (Exception ex)
                {
                    TempData["message"] = "exception thrown adding role: " + ex.GetBaseException().Message;
                }
            }

            return RedirectToAction("Index");
        }

        // delete a role, if it has users in it send user to confirmation view
        public ActionResult DeleteRole(string roleName)
        {
            // find the role object to delete
            IdentityRole role = roleManager.FindByName(roleName);
            // if role does not exist, cannot delete
            if (role == null)
            {
                TempData["message"] = "role not on file: " + roleName;
            }
            // if role is administrator disallow user from deleting
            if (role.Name.ToLower() == "administrators")
            {
                TempData["message"] = "cannot delete administators";
                return RedirectToAction("Index");
            }
            // if there are no users in the role proceed with delete process
            if (role.Users.Count == 0)
            {
                try
                {
                    // get a result from rolemanager delete
                    IdentityResult result = roleManager.Delete(role);
                    // if result successful message role deleted otherwise show errors
                    if (result.Succeeded)
                    {
                        TempData["message"] = "role deleted: " + roleName;
                    }
                    else
                    {
                        TempData["message"] = "delete failed: " + result.Errors.ToList()[0];
                    }
                }
                catch (Exception ex)
                {
                    TempData["message"] = "exception deleting role: " + ex.GetBaseException().Message;
                }
            }
            // if there are users in the role send user to confirm delete role
            else
            {
                // add all the members of the role to a list and send this list to the delete role view
                List<ApplicationUser> members = new List<ApplicationUser>();
                foreach (var item in role.Users)
                {
                    members.Add(userManager.FindById(item.UserId));
                }
                return View(members);
            }
            ViewBag.roleName = roleName;
            return RedirectToAction("Index");
        }

        // comfirm delete a role after selecting delete role button
        [HttpPost, ActionName("DeleteRole")]
        public ActionResult DeleteRoleConfirm(string roleName)
        {
            // boolean representing the checkbox on delete role view
            bool CanDeleteUser = false;
            // if checkbox was checked set bool to true
            if (Request["deleteUser"] == "on")
            {
                CanDeleteUser = true;
            }
            // find the role to delete
            var role = roleManager.FindByName(roleName);
            // declare result
            IdentityResult result;
            // if there are users in the role and canDeleteUser is false, send user back to the view,
            // they must select the checkbox to delete the users from role in order for role to be deleted
            if (role.Users.Count() > 0 && !CanDeleteUser)
            {
                TempData["message"] = "Must check delete all users";
                return RedirectToAction("DeleteRole", new { roleName = role.Name });
            }
            // if there are no users in the role or canDeleteUser is true proceed with delete role process
            else if (role.Users.Count() == 0 || CanDeleteUser)
	        {
		        try 
	            {	
                    // set result to rolemanager delete of role to delete
		            result = roleManager.Delete(role);
                    // if result successful, show message that role was deleted and send user to index
                    if (result.Succeeded)
	                {
		                TempData["message"] = "role deleted";
                        return RedirectToAction("Index");
	                }
                    else
	                {
                        throw new Exception("error deleting role: " + result.Errors.ToList()[0]);
	                }
	            }
	            catch (Exception ex)
	            {
		            TempData["message"] = "Exception deleting role " + ex.GetBaseException().Message;
	            }
	        }

            return RedirectToAction("Index");
        }

        // list members of a role
        public ActionResult MemberList(string roleName)
        {
            // get role object from the rolename passed into controller
            IdentityRole role = roleManager.FindByName(roleName);

            // get list of all users in the role
            List<IdentityUserRole> userRoles = role.Users.ToList();
            // put users of role into ApplicationUser list
            List<ApplicationUser> members = new List<ApplicationUser>();
            foreach (var item in userRoles)
            {
                members.Add(userManager.FindById(item.UserId));
            }
            // get list of all users
            List<ApplicationUser> allUsers = userManager.Users.ToList();
            // put non members of this role into a list
            List<ApplicationUser> nonMembers = new List<ApplicationUser>();
            foreach (var item in allUsers)
            {
                if (!members.Contains(item))
                {
                    nonMembers.Add(item);
                }
            }

            ViewBag.roleName = roleName;
            ViewBag.userName = User.Identity.Name;
            ViewBag.userId = new SelectList(nonMembers, "Id", "userName");

            return View(members);
        }

        // add a user to a role and return to member list
        [HttpPost]
        public ActionResult AddToRole()
        {
            // get user id and role name
            var userId = Request["userId"];
            var roleNameValue = Request["roleName"];
            // if either are null go back to index
            if (userId == null || roleNameValue == null)
            {
                TempData["message"] = "No Role or user found";
                return RedirectToAction("Index");
            }

            // get the role that the user will be added to
            var role = roleManager.FindByName(roleNameValue);
            // get the user object that we will add to the role
            ApplicationUser user = userManager.FindById(userId);
            // if user and role exist add the user to the role
            if (user != null && role != null)
            {
                IdentityResult identityResult = userManager.AddToRole(userId: user.Id,role: role.Name);
            }

            return RedirectToAction("MemberList", new { roleName = role.Name });
        }

        // remove a user from a role
        public ActionResult RemoveFromRole(string userId, string roleName)
        {
            try
            {
                // if user id is null go back to index
                if (userId == null)
                {
                    TempData["message"] = "No User Selected";
                    return RedirectToAction("Index");
                }
                // get user that is to be removed from role
                ApplicationUser user = userManager.FindById(userId);
                // if user to be removed is the same as the logged in user disallow removal from role
                if (user.UserName == User.Identity.Name)
                {
                    TempData["message"] = "Cannot delete yourself";
                    return RedirectToAction("MemberList", new { roleName = roleName });
                }
                // get the role that the user will be removed from
                var role = roleManager.FindByName(roleName);
                // if user was found proceed with removal
                if (user != null)
                {
                    // get result object from removing user from role
                    IdentityResult result = userManager.RemoveFromRole(userId: user.Id, role: role.Name);
                    // if result was successful show message that user was removed, otherwise show errors
                    if (result.Succeeded)
                    {
                        TempData["message"] = "user " + user.UserName + "was removed from role";
                    }
                    else
                    {
                        TempData["message"] = "Cannot remove user: " + result.Errors.ToList()[0];
                    }
                }

                return RedirectToAction("MemberList", new { roleName = roleName });
            }
            catch (Exception ex)
            {
                while (ex.InnerException != null)
                {
                    ex = ex.InnerException;
                    ModelState.AddModelError("", "error deleteing user: " + ex.Message);
                }
            }
            return RedirectToAction("Index");
        }
    }
}