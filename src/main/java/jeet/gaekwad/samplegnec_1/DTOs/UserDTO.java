package jeet.gaekwad.samplegnec_1.DTOs;

import jeet.gaekwad.samplegnec_1.Model.Accounts;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long accountId;
    private String username;
    private String role;
    private String email;
    private String profilePhoto;

    // Constructor from Account entity
    public UserDTO(Accounts account) {
        this.accountId = account.getAccountId();
        this.username = account.getUsername();
        this.role = account.getRole();
        this.email = account.getEmail();
        this.profilePhoto = String.valueOf(account.getProfilePhoto());
    }

    // Getters (NO setters if you want immutability)
    public Long getAccountId() { return accountId; }
    public String getUsername() { return username; }
    // ... other getters
}
