package com.app.tddt4iots.entities;

import com.app.tddt4iots.enums.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.*;
import java.lang.*;

import jakarta.persistence.*;

@Entity
@Table(name = "EnergyRateSettings")
@Data
@NoArgsConstructor
public class EnergyRateSettings {
    
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long {$idClass};
     
    
}    
