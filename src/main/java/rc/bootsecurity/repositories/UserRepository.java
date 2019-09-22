package rc.bootsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import rc.bootsecurity.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
