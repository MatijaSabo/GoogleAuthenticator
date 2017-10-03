using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace GoogleAuthenticator.Models
{
    [MetadataType(typeof(UserMetaData))]
    public partial class User
    {
        public string ComfirmPassword { get; set; }
    }

    public class UserMetaData
    {
        [Display(Name = "First name")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "First name is requred")]
        public string FirstName { get; set; }

        [Display(Name = "Last name")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "Last name is requred")]
        public string LastName { get; set; }

        [Display(Name = "User name")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "User name is requred")]
        public string UserName { get; set; }
        
        [Required(AllowEmptyStrings = false, ErrorMessage = "Password is requred")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage = "Minimum 6 characters required")]
        public string Password { get; set; }

        [Display(Name = "Comfirm Password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Confirm password and password do not match")]
        public string ComfirmPassword { get; set; }

        [Display(Name = "Email")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "Email is requred")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }
    }
}