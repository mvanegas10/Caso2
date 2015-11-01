package generator;



import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {

	/**
	 * Generador de carga
	 */
	private LoadGenerator generator;

	/**
	 * Constructor
	 */
	public Generator(){

		 // Numero de tareas
		int numberOfTasks=10;
		// Tiempo en milisegundos
		int gapBeetwenTasks=20;

		ClientServerTask work =createTask();
		generator=new LoadGenerator("prueba", numberOfTasks, work, gapBeetwenTasks);
		generator.generate();


	}

	private ClientServerTask createTask(){
		return new ClientServerTask();
	}

	public static void main(String[] args) {
		Generator gen=new Generator();

	}

}
