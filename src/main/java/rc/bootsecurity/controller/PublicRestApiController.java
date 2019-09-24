package rc.bootsecurity.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import rc.bootsecurity.model.User;
import rc.bootsecurity.repositories.UserRepository;

import java.util.List;

@RestController
@RequestMapping("api/public")
@CrossOrigin
public class PublicRestApiController {

    private final UserRepository userRepository;

    public PublicRestApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // available to all authenticated user
    @GetMapping("test")
    public String test() {
        return "API Test 1";
    }

    // available to managers
    @GetMapping("management/reports")
    public String reports() {
        return "Some report Data";
    }

    // available to ROLE_ADMIN
    @GetMapping("admin/users")
    public List<User> getUsers() {
        return this.userRepository.findAll();
    }

}
