package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;

@Entity
@Table(name = "EnergyFlowSensor")
@Data
@NoArgsConstructor
public class EnergyFlowSensor {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
     
    @Column(name = "currentFlowRate", nullable = true, unique = true) 
    private Float currentFlowRate; 
 
    @Column(name = "totalConsumptions", nullable = false, unique = false) 
    private Float totalConsumptions; 
 
    
}    
