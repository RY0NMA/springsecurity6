package com.debuggeandoideas.app_security.Entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name="ROL")
public class Roles {
	
	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	@Column(name="ID_ROL")
	public int idRol;
	@Column(name="NOMBRE_ROL")
	public String rol;
	@Column(name="DESCRIPCION")
	public String description;
	public Roles(int idRol, String rol, String description) {
		super();
		this.idRol = idRol;
		this.rol = rol;
		this.description = description;
	}
	public Roles() {
		super();
	}
	public int getIdRol() {
		return idRol;
	}
	public void setIdRol(int idRol) {
		this.idRol = idRol;
	}
	public String getRol() {
		return rol;
	}
	public void setRol(String rol) {
		this.rol = rol;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	@Override
	public String toString() {
		return "Roles [idRol=" + idRol + ", rol=" + rol + ", description=" + description + "]";
	}
	

}
