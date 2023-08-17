package com.debuggeandoideas.app_security.Repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.debuggeandoideas.app_security.Entity.Partner;

public interface PartnerRepository extends CrudRepository<Partner, Integer>{
	
	Optional<Partner> findByClientId(String clientId);

}
