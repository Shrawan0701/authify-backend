package in.shrawan.authify.io;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ProfileRequest {

    @NotBlank(message = "Name should be not empty")
    private String name;
    @Email(message = "Enter valid email")
    @NotNull(message = "Email should not be empty")
    private String email;
    @Size(min = 6, message = "Password should be minimum 6 characters")
    private String password;


}
