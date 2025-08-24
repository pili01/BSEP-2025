package com.bsep.pki.repositories;

import com.bsep.pki.models.CsrRequest;
import com.bsep.pki.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface CsrRequestRepository extends JpaRepository<CsrRequest, Long> {
    

    List<CsrRequest> findByStatus(String status);

    List<CsrRequest> findByStatusAndOrganization(String status, String organization);

    List<CsrRequest> findByTargetUser(User targetUser);

    List<CsrRequest> findByUploadingUser(User uploadingUser);

    Optional<CsrRequest> findByCommonNameAndStatus(String commonName, String status);

    List<CsrRequest> findByOrganization(String organization);

    List<CsrRequest> findByStatusAndOrganizationOrderByUploadDateDesc(String status, String organization);

    List<CsrRequest> findByCaIssuerSerialNumber(String caIssuerSerialNumber);

    List<CsrRequest> findByCsrPemContent(String csrPemContent);
}
