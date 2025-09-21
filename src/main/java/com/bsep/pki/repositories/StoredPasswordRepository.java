package com.bsep.pki.repositories;

import com.bsep.pki.models.StoredPassword;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface StoredPasswordRepository extends MongoRepository<StoredPassword, String> {

    @Query("{ '$or': [ { 'ownerId': ?0 }, { 'shares.userId': ?0 } ] }")
    List<StoredPassword> findAllMyPasswords(Long userId);

}
