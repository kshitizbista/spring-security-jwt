package rc.bootsecurity.bootstrap;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import rc.bootsecurity.model.User;
import rc.bootsecurity.repositories.UserRepository;

import java.util.Arrays;
import java.util.List;

@Component
public class DbInit implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DbInit(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {

        this.userRepository.deleteAll();

        User kshitiz = new User("kshitiz", passwordEncoder.encode("kshitiz"), "USER", "");
        User admin = new User("admin", passwordEncoder.encode("admin"), "ADMIN", "ACCESS_TEST1,ACCESS_TEST2");
        User manager = new User("manager", passwordEncoder.encode("manager"), "MANAGER", "ACCESS_TEST2");

        List<User> users = Arrays.asList(kshitiz, admin, manager);
        this.userRepository.saveAll(users);
    }
}
