package com.bsep.pki.models;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "stored_passwords")
public class StoredPassword {
    @Id
    private String id;
    private String siteName;
    private String username;
    private Long ownerId;
    private List<PasswordShare> shares;
}
