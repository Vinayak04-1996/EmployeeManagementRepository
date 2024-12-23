﻿using EmpManagementSystemAPI.EmployeeService;
using EmpManagementSystemAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EmployeeManagementSystemAPP.Controllers
{
    public class UserController : Controller
    {
        private readonly EmpManagementSystemAPI.Controllers.UserController _userController;
        //private readonly HttpClient _httpClient;
        private readonly IEmployee _employee;
        public UserController(EmpManagementSystemAPI.Controllers.UserController userController)
        {
            _userController = userController;
        }

        // GET: UserController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: UserController/Create
        [HttpPost]
        //[ValidateAntiForgeryToken]
        public ActionResult Create(User user)
        {
            try
            {
                var adduser = _userController.AddUser(user);
                return RedirectToAction("Login","Login");
            }
            catch
            {
                ModelState.AddModelError(string.Empty, "An error occurred while creating the user. Please try again.");
                return View();
            }
        }

        // GET: UserController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: UserController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: UserController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: UserController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
