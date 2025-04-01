namespace API.Controllers{
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Authorization;

    public class UserModel : IdentityUser{
        public string? Role {get; set; } = "User";
        public string? CurrentPassword {get; set; }
        public string? NewPassword {get; set; }
    }

    [Route("/[controller]")]
    [ApiController]
    public class UserController : ControllerBase{
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(UserManager<IdentityUser> userManager){
            _userManager = userManager;
        }

        // Get all users
        [HttpGet]
        [Authorize(Policy = "RequireAdminRole")]
        public async Task<ActionResult<IList<IdentityUser>>> GetUsers(){
            var result = await _userManager.GetUsersInRoleAsync("User");

            if(result != null){
                return Ok(result);
            }

            return BadRequest(new{message="Error found"});
        }

        // Create endpoint
        [HttpPost("create")]
        [Authorize(Policy="RequireAdminRole")]
        public async Task<IActionResult> CreateUser([FromBody] UserModel userModel){
            var user = new IdentityUser{ UserName = userModel.Email, Email = userModel.Email};


            var result = await _userManager.CreateAsync(user);
            if(result.Succeeded){
                await _userManager.AddToRoleAsync(user, userModel.Role);
                return Ok(new {message = "User registered succesfully"});
            }

            
            return BadRequest(new{message="Not created", errors = result.Errors});
            
            //    return CreatedAtAction("GetTodoItem", new { id = todoItem.Id }, todoItem);
            //return CreatedAtAction( new { email = user.Email }, user);
        }

        // Get endpoint
        [HttpGet("{id}")]
        public async Task<ActionResult<IdentityUser>> GetUserById(string id){

            var result = await _userManager.FindByIdAsync(id);
            if(result == null){
                return NotFound();
            }
            else{
                return result;
            }
        }


        // Put endpoint
        [HttpPut("{id}")]
        [Authorize(Policy = "RequireAdminRole")]
        public async Task<IActionResult> UpdateUser(string id,[FromBody] UserModel userModel)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            user.UserName = userModel.Email;
            user.Email = userModel.Email;

            var result = await _userManager.UpdateAsync(user);

            if(result.Succeeded){
                return Ok(new{message = "User updated succesfully!"});
            }
            
            return BadRequest(new {message="not updated",errors = result.Errors});
        }

        // Add password
        [HttpPut("{id}/add_password")]        
        [Authorize(Policy = "RequireAdminRole")]
        public async Task<IActionResult> AddUserPassword(string id, [FromBody] UserModel userModel)
        {
            var user = await _userManager.FindByIdAsync(id);

            if (user == null)
            {
                return NotFound();
            }

            if(!(await _userManager.HasPasswordAsync(user))){
                var result = await _userManager.AddPasswordAsync(user, userModel.NewPassword);   

                if(result.Succeeded){
                return Ok(new{message = "Password updated succesfully!"});
                }
            
                return BadRequest(new {message="Password not updated", errors = result.Errors});
            }
            else{
                return BadRequest(new {message="User already has a password!"});
            }
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "RequireAdminRole")]
        public async Task<IActionResult> DeleteUser(string id){
            var user = await _userManager.FindByIdAsync(id);
            
            if (user == null)
            {
                return NotFound();
            } 

            var result = await _userManager.DeleteAsync(user);

            if(result.Succeeded){
                return Ok( new {message="User {id} deleted succesfully"});
            }

            return BadRequest( new{ message="User not deleted", error=result.Errors});

        }

    }
}