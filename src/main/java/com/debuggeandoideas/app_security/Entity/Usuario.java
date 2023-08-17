package com.debuggeandoideas.app_security.Entity;

import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Entity
@Table(name="USUARIOS")
public class Usuario {

	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	@Column(name="ID_USUARIO")
	public int idUser;
	@Column(name="NOMBRE")
	public String name;
	@Column(name="USERNAME")
	public String user;
	@Column(name="PASSWORD")
	public String pass;
	@Column(name="NO_EMPLEADO")
	public int empleado;
	@Column(name="CORREO")
	public String email;
	/*
	@Column(name="ID_ROL")
	public int idRole;
	@Column(name="NOMBRE_ROL")
	*/
	@OneToMany(fetch = FetchType.EAGER)
    @JoinColumn(name = "ID_USUARIO")
    private List<Roles> roles;
	public Usuario(int idUser, String name, String user, String pass, int empleado, String email, List<Roles> roles) {
		super();
		this.idUser = idUser;
		this.name = name;
		this.user = user;
		this.pass = pass;
		this.empleado = empleado;
		this.email = email;
		this.roles = roles;
	}
	public Usuario() {
		super();
	}
	public int getIdUser() {
		return idUser;
	}
	public void setIdUser(int idUser) {
		this.idUser = idUser;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public String getPass() {
		return pass;
	}
	public void setPass(String pass) {
		this.pass = pass;
	}
	public int getEmpleado() {
		return empleado;
	}
	public void setEmpleado(int empleado) {
		this.empleado = empleado;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public List<Roles> getRoles() {
		return roles;
	}
	public void setRoles(List<Roles> roles) {
		this.roles = roles;
	}
	@Override
	public String toString() {
		return "Usuario [idUser=" + idUser + ", name=" + name + ", user=" + user + ", pass=" + pass + ", empleado="
				+ empleado + ", email=" + email + ", roles=" + roles + "]";
	}
	
}
