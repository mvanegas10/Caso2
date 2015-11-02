package generator;



import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private static int fallidas;
	
	/**
	 * Generador de carga
	 */
	private LoadGenerator generator;

	/**
	 * Constructor
	 */
	public Generator(){

		 // Numero de tareas
		int numberOfTasks=400;

		// Tiempo en milisegundos
		int gapBeetwenTasks=20;

		ClientServerTask work =createTask();
		generator=new LoadGenerator("prueba", numberOfTasks, work, gapBeetwenTasks);
		generator.generate();

	}

	/**
	 * Aumenta fallidas
	 */
	public void aumentarFallidas(){
		fallidas ++;
	}
	
	/**
	 * Crea una tarea
	 * @return
	 */
	private ClientServerTask createTask(){
		return new ClientServerTask(this);
	}

	/**
	 * main
	 * @param args
	 */
	public static void main(String[] args) {
		fallidas = 0;
		Generator gen=new Generator();
		System.out.println("FIN DE CARGA");
		System.out.println("Hubo " + fallidas + " tareas fallidas.\n");

	}

}
